//! Camera enrollment via xdg-desktop-portal Camera + PipeWire.
//!
//! Aaron's UX: one button "Watch for QR", live preview with a
//! reticle so the user can frame the QR, first successful decode
//! ends the watch and populates the preview rows. No manual capture
//! step — the system locks on as soon as it sees one.
//!
//! Architecture (validated by `examples/camera_spike.rs`):
//!
//! 1. `ashpd::desktop::camera::request()` does the portal handshake
//!    and hands back `(OwnedFd, Vec<Stream>)`. The fd is a PipeWire
//!    socket scoped to camera nodes only; the Stream metadata gives
//!    us a node id to target.
//! 2. PipeWire init + `connect_fd_rc(fd)` connects to that scoped
//!    socket. We then create a Stream with `MEDIA_ROLE=Camera` and
//!    request a YUY2 640x480 @ 30fps format.
//! 3. After format negotiation fixates, we MUST push back a
//!    `SPA_TYPE_OBJECT_ParamBuffers` pod declaring buffer shape +
//!    accepted data types (MemPtr/MemFd, NOT DmaBuf because our
//!    `MAP_BUFFERS` stream flag can't auto-mmap dmabufs). Without
//!    this v4l2 sources error out on `use_buffers: -22`.
//! 4. Per-frame: extract the Y plane (every other byte of YUY2),
//!    push it as a grayscale Slint Image preview, run
//!    `enroll::qr::decode_grayscale`. On Ok we marshal payloads to
//!    the UI thread via `apply_decoded_rows` and call
//!    `mainloop.quit()` from inside the process callback (same
//!    thread that owns the loop, the only safe way to stop).
//!
//! Threading: UI thread spawns a worker that owns the entire
//! PipeWire stack (MainLoopRc is `!Send`, so it can't be passed
//! across threads — must be constructed in the worker). Cross-
//! thread shutdown is via `Arc<AtomicBool>` checked in the process
//! callback. Per-frame UI updates marshal via
//! `slint::invoke_from_event_loop`.
//!
//! Format choice: we hard-code YUY2 640x480 because that's what
//! the OBSBOT Meet 2 (the test hardware) exposes as raw video at a
//! reasonable size — anything larger is MJPEG. 640x480 is enormous
//! overprovisioning for QR decode (rqrr handles much smaller).
//! Cameras that don't expose YUYV at this size will fail
//! negotiation and the worker will surface an error to the UI;
//! production polish can broaden the format set then (likely add
//! MJPEG decode via the `image` crate's JPEG path).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use pipewire as pw;
use pw::properties::properties;
use pw::spa;
use pw::spa::pod::Pod;
use slint::{ComponentHandle, Image, Rgba8Pixel, SharedPixelBuffer};

use tocken_core::enroll;

use crate::{enroll as enroll_mod, AppState, MainWindow};

/// Per-app shared handle on the active camera session. `None` when
/// the camera isn't running. Held in a `Mutex` so start/stop from
/// the UI thread is serialized.
pub(crate) type SharedCamera = Arc<Mutex<Option<CameraSession>>>;

/// Lives in `SharedCamera` while a watch is active. Holds only the
/// stop signal — the actual PipeWire objects live on the worker
/// thread (MainLoopRc is `!Send`). On drop we set the stop flag so
/// the worker exits even if the caller forgot to call `stop()`.
pub(crate) struct CameraSession {
    stop: Arc<AtomicBool>,
}

impl CameraSession {
    fn signal_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for CameraSession {
    fn drop(&mut self) {
        self.signal_stop();
    }
}

pub(crate) fn new_shared() -> SharedCamera {
    Arc::new(Mutex::new(None))
}

pub(crate) fn wire_camera(ui: &MainWindow, camera: SharedCamera) {
    {
        let weak = ui.as_weak();
        let camera = camera.clone();
        ui.global::<AppState>().on_start_camera_watch(move || {
            if let Some(ui) = weak.upgrade() {
                start_session(&ui, &camera);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let camera = camera.clone();
        ui.global::<AppState>().on_stop_camera_watch(move || {
            stop_session(&camera);
            if let Some(ui) = weak.upgrade() {
                let state = ui.global::<AppState>();
                state.set_enroll_camera_watching(false);
                state.set_enroll_camera_status("".into());
            }
        });
    }
}

fn start_session(ui: &MainWindow, camera: &SharedCamera) {
    let mut guard = camera.lock().unwrap();
    if guard.is_some() {
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_worker = stop.clone();
    let weak = ui.as_weak();

    let state = ui.global::<AppState>();
    state.set_enroll_camera_watching(true);
    state.set_enroll_camera_status("Hold a QR code in front of the camera…".into());
    state.set_enroll_error("".into());

    *guard = Some(CameraSession { stop });
    drop(guard);

    let camera = camera.clone();
    thread::spawn(move || {
        let outcome = run_camera_loop(stop_for_worker, weak.clone());

        // Worker is exiting either way — clear the slot so a fresh
        // start_session won't be blocked. Holds the lock briefly.
        if let Ok(mut guard) = camera.lock() {
            *guard = None;
        }

        // Clear watching state. If `outcome` is Err we surface it;
        // a successful decode already cleared `watching` from the
        // UI thread before quit, so this is mostly a safety net.
        let weak_for_clear = weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak_for_clear.upgrade() {
                let state = ui.global::<AppState>();
                if state.get_enroll_camera_watching() {
                    state.set_enroll_camera_watching(false);
                    state.set_enroll_camera_status("".into());
                }
                if let Err(msg) = outcome {
                    state.set_enroll_error(msg.into());
                }
            }
        });
    });
}

fn stop_session(camera: &SharedCamera) {
    if let Ok(guard) = camera.lock() {
        if let Some(session) = guard.as_ref() {
            session.signal_stop();
        }
        // Don't take the session out here — let the worker thread
        // clear it once the mainloop has actually exited. Otherwise
        // a quick Stop+Start could race a still-running stream.
    }
}

/// Idempotent stop: signals shutdown if a session is running, no-op
/// otherwise. Use from any lifecycle hook (cancel-enroll, save,
/// open-enroll) where we want to ensure the camera isn't holding the
/// device open.
pub(crate) fn stop_camera_if_running(camera: &SharedCamera) {
    stop_session(camera);
}

/// Per-callback state. Held inside the stream listener via
/// `add_local_listener_with_user_data`; never crosses the worker
/// thread (so non-Send fields are fine).
struct UserData {
    format: spa::param::video::VideoInfoRaw,
    weak: slint::Weak<MainWindow>,
    stop: Arc<AtomicBool>,
    mainloop: pw::main_loop::MainLoopRc,
    decoded: bool,
}

fn run_camera_loop(stop: Arc<AtomicBool>, weak: slint::Weak<MainWindow>) -> Result<(), String> {
    let requested = pollster::block_on(ashpd::desktop::camera::request())
        .map_err(|e| format!("portal: {e}"))?;
    let (fd, streams) = requested.ok_or_else(|| "no camera available".to_string())?;
    let target_node_id = streams.first().map(|s| s.node_id());

    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None).map_err(|e| format!("mainloop: {e}"))?;
    let context =
        pw::context::ContextRc::new(&mainloop, None).map_err(|e| format!("context: {e}"))?;
    let core = context
        .connect_fd_rc(fd, None)
        .map_err(|e| format!("connect: {e}"))?;

    let stream = pw::stream::StreamBox::new(
        &core,
        "tocken-camera",
        properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Camera",
        },
    )
    .map_err(|e| format!("stream new: {e}"))?;

    let user_data = UserData {
        format: Default::default(),
        weak,
        stop,
        mainloop: mainloop.clone(),
        decoded: false,
    };

    let _listener = stream
        .add_local_listener_with_user_data(user_data)
        .state_changed(|_, _, _, _| {})
        .param_changed(|stream, ud, id, param| {
            let Some(param) = param else {
                return;
            };
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Ok((mt, ms)) = spa::param::format_utils::parse_format(param) else {
                return;
            };
            if mt != spa::param::format::MediaType::Video
                || ms != spa::param::format::MediaSubtype::Raw
            {
                return;
            }
            ud.format.parse(param).expect("parse VideoInfoRaw");
            let w = ud.format.size().width;
            let h = ud.format.size().height;
            let stride = (w * 2) as i32;
            let size = stride * h as i32;
            let buffers_pod = build_buffers_pod(stride, size);
            let pod_bytes: Vec<u8> = match spa::pod::serialize::PodSerializer::serialize(
                std::io::Cursor::new(Vec::new()),
                &spa::pod::Value::Object(buffers_pod),
            ) {
                Ok((cursor, _)) => cursor.into_inner(),
                Err(_) => return,
            };
            let Some(pod) = Pod::from_bytes(&pod_bytes) else {
                return;
            };
            let _ = stream.update_params(&mut [pod]);
        })
        .process(|stream, ud| {
            // Stop signal: the only safe place to call mainloop.quit()
            // is from inside its own thread, so the process callback
            // is where shutdown materializes.
            if ud.stop.load(Ordering::SeqCst) || ud.decoded {
                ud.mainloop.quit();
                return;
            }

            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let datas = buffer.datas_mut();
            if datas.is_empty() {
                return;
            }
            let chunk_size = datas[0].chunk().size() as usize;
            let chunk_offset = datas[0].chunk().offset() as usize;
            let Some(buf) = datas[0].data() else {
                return;
            };
            if chunk_size == 0 || chunk_offset + chunk_size > buf.len() {
                return;
            }
            let frame = &buf[chunk_offset..chunk_offset + chunk_size];
            let w = ud.format.size().width;
            let h = ud.format.size().height;
            if w == 0 || h == 0 {
                return;
            }

            // Spike validated YUY2-only path. Other formats fall
            // through silently — we'd negotiate them out anyway.
            if !matches!(ud.format.format(), spa::param::video::VideoFormat::YUY2) {
                return;
            }

            let pixels = (w as usize) * (h as usize);
            if frame.len() < pixels * 2 {
                return;
            }
            let mut luma = Vec::with_capacity(pixels);
            for c in frame[..pixels * 2].chunks_exact(2) {
                luma.push(c[0]);
            }

            push_preview(&ud.weak, w, h, &luma);

            if let Ok(payloads) = enroll::qr::decode_grayscale(w, h, &luma) {
                ud.decoded = true;
                push_decode_success(&ud.weak, payloads);
                ud.mainloop.quit();
            }
        })
        .register()
        .map_err(|e| format!("listener: {e}"))?;

    let format_pod = build_format_pod();
    let pod_bytes: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(format_pod),
    )
    .map_err(|e| format!("format pod serialize: {e:?}"))?
    .0
    .into_inner();
    let mut params = [Pod::from_bytes(&pod_bytes).ok_or_else(|| "invalid format pod".to_string())?];

    stream
        .connect(
            spa::utils::Direction::Input,
            target_node_id,
            pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .map_err(|e| format!("stream connect: {e}"))?;

    mainloop.run();
    Ok(())
}

/// Per-frame preview push. Builds a grayscale-as-RGBA pixel buffer
/// from the Y plane and marshals it to the UI thread, where it
/// becomes a `slint::Image`. Image itself is `!Send` (VRc inside),
/// but `SharedPixelBuffer<Rgba8Pixel>` is Send because Rgba8Pixel
/// is just bytes — so we ship the buffer and construct the Image
/// on the UI side. ~37MB/s of allocations at 30fps × 640x480 × 4
/// bytes is fine; if profiling flags it, swap in a single-slot
/// `Mutex<Option<SharedPixelBuffer>>` mailbox with backpressure.
fn push_preview(weak: &slint::Weak<MainWindow>, w: u32, h: u32, luma: &[u8]) {
    let mut buf = SharedPixelBuffer::<Rgba8Pixel>::new(w, h);
    let pixels = buf.make_mut_slice();
    for (i, &y) in luma.iter().enumerate().take(pixels.len()) {
        pixels[i] = Rgba8Pixel {
            r: y,
            g: y,
            b: y,
            a: 255,
        };
    }
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            let image = Image::from_rgba8(buf);
            ui.global::<AppState>().set_enroll_camera_frame(image);
        }
    });
}

/// First successful decode: stop watching, surface payloads via the
/// existing file-rows landing pad. The user reviews the rows and
/// clicks Save (which dispatches through `save-enroll-file`, just
/// like clipboard imports).
fn push_decode_success(weak: &slint::Weak<MainWindow>, payloads: Vec<String>) {
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let rows = enroll::file::decode_payloads(payloads);
        let state = ui.global::<AppState>();
        state.set_enroll_camera_watching(false);
        state.set_enroll_camera_status("Got it.".into());
        enroll_mod::apply_decoded_rows(&state, String::new(), rows);
    });
}

fn build_format_pod() -> spa::pod::Object {
    spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaType,
            Id,
            spa::param::format::MediaType::Video
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaSubtype,
            Id,
            spa::param::format::MediaSubtype::Raw
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFormat,
            Id,
            spa::param::video::VideoFormat::YUY2
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoSize,
            Rectangle,
            spa::utils::Rectangle {
                width: 640,
                height: 480
            }
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFramerate,
            Fraction,
            spa::utils::Fraction { num: 30, denom: 1 }
        ),
    )
}

/// SPA_TYPE_OBJECT_ParamBuffers pod. The libspa Rust crate doesn't
/// expose BUFFERS_* keys as a friendly enum, so we hand-build the
/// Object using raw `Property::new(spa_sys_const, Value::Int(...))`.
/// We accept MemPtr and MemFd (both mmap-friendly with our
/// `MAP_BUFFERS` flag) but explicitly NOT DmaBuf — auto-mapping
/// dmabufs would require a different code path.
fn build_buffers_pod(stride: i32, size: i32) -> spa::pod::Object {
    use pw::spa::pod::{ChoiceValue, Object, Property, Value};
    use pw::spa::utils::{Choice, ChoiceEnum, ChoiceFlags};

    let memptr_bit: i32 = 1 << pw::spa::sys::SPA_DATA_MemPtr;
    let memfd_bit: i32 = 1 << pw::spa::sys::SPA_DATA_MemFd;

    Object {
        type_: spa::utils::SpaTypes::ObjectParamBuffers.as_raw(),
        id: spa::param::ParamType::Buffers.as_raw(),
        properties: vec![
            Property::new(
                pw::spa::sys::SPA_PARAM_BUFFERS_buffers,
                Value::Choice(ChoiceValue::Int(Choice::<i32>(
                    ChoiceFlags::empty(),
                    ChoiceEnum::<i32>::Range {
                        default: 8,
                        min: 2,
                        max: 32,
                    },
                ))),
            ),
            Property::new(pw::spa::sys::SPA_PARAM_BUFFERS_blocks, Value::Int(1)),
            Property::new(pw::spa::sys::SPA_PARAM_BUFFERS_size, Value::Int(size)),
            Property::new(pw::spa::sys::SPA_PARAM_BUFFERS_stride, Value::Int(stride)),
            Property::new(
                pw::spa::sys::SPA_PARAM_BUFFERS_dataType,
                Value::Choice(ChoiceValue::Int(Choice::<i32>(
                    ChoiceFlags::empty(),
                    ChoiceEnum::<i32>::Flags {
                        default: memptr_bit | memfd_bit,
                        flags: vec![memptr_bit, memfd_bit],
                    },
                ))),
            ),
        ],
    }
}
