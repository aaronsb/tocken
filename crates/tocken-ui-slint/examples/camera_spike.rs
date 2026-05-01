//! Camera spike: portal handshake → pipewire stream → first decode → exit.
//!
//! Run with:
//!     cargo run -p tocken-ui-slint --example camera_spike
//!
//! Throwaway code. Validates the unknowns outside the slint app:
//! 1. ashpd::desktop::camera::request() returns Ok and surfaces the
//!    KDE/GNOME portal prompt
//! 2. The OwnedFd it hands back drives a pipewire connection
//! 3. Format negotiation lands on a video format we can decode
//!    (YUYV / RGB / RGBA / I420 — first one we recognize wins)
//! 4. tocken_core::enroll::qr::decode_grayscale (Y plane) or decode_rgba
//!    returns Ok with at least one payload when a QR is held in front
//!    of the camera
//!
//! Hold a QR-bearing image in front of the webcam after the
//! "Negotiated format..." line prints. The spike exits on first
//! successful decode.

use pipewire as pw;
use pw::properties::properties;
use pw::spa;
use pw::spa::pod::Pod;

use tocken_core::enroll::qr;

/// Per-stream state shared with the listener callbacks. Held by
/// `add_local_listener_with_user_data`; the closures see `&mut UserData`.
struct UserData {
    format: spa::param::video::VideoInfoRaw,
    decoded: bool,
    /// First-frame diagnostics flag — print buffer shape exactly once
    /// so we can debug format-vs-data mismatch (e.g. negotiated YUY2
    /// but source actually delivering MJPEG).
    diagnosed: bool,
    /// Cloned mainloop so the process callback can quit on first decode.
    /// MainLoopRc is Rc-counted internally; cheap to clone.
    mainloop: pw::main_loop::MainLoopRc,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Requesting camera access via xdg-desktop-portal...");
    let requested = pollster::block_on(ashpd::desktop::camera::request())?;
    let (fd, streams) = requested.ok_or("portal returned no camera (none present?)")?;
    println!(
        "Portal granted access. {} stream(s) available:",
        streams.len()
    );
    for s in &streams {
        println!("  node_id={} props={:?}", s.node_id(), s.properties());
    }
    let target_node_id = streams.first().map(|s| s.node_id());
    println!("Targeting node_id={:?}", target_node_id);

    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_fd_rc(fd, None)?;

    let stream = pw::stream::StreamBox::new(
        &core,
        "tocken-camera-spike",
        properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Camera",
        },
    )?;

    let user_data = UserData {
        format: Default::default(),
        decoded: false,
        diagnosed: false,
        mainloop: mainloop.clone(),
    };

    let _listener = stream
        .add_local_listener_with_user_data(user_data)
        .state_changed(|_, _, old, new| {
            println!("Stream state: {:?} -> {:?}", old, new);
        })
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
            ud.format
                .parse(param)
                .expect("parse VideoInfoRaw");
            let w = ud.format.size().width;
            let h = ud.format.size().height;
            println!(
                "Negotiated format: {:?} {}x{} @ {}/{} fps",
                ud.format.format(),
                w,
                h,
                ud.format.framerate().num,
                ud.format.framerate().denom.max(1),
            );

            // Push a Buffers param response so the source knows what
            // kind of buffers we'll accept. v4l2 sources won't transition
            // out of Paused without this — they error on use_buffers
            // because their default DmaBuf preference doesn't match our
            // MAP_BUFFERS flag.
            //
            // YUYV is 2 bytes per pixel.
            let stride = (w * 2) as i32;
            let size = stride * h as i32;
            let buffers_pod = build_buffers_pod(stride, size);
            let pod_bytes: Vec<u8> = match spa::pod::serialize::PodSerializer::serialize(
                std::io::Cursor::new(Vec::new()),
                &spa::pod::Value::Object(buffers_pod),
            ) {
                Ok((cursor, _size)) => cursor.into_inner(),
                Err(e) => {
                    eprintln!("buffers pod serialize: {e}");
                    return;
                }
            };
            let Some(pod) = Pod::from_bytes(&pod_bytes) else {
                eprintln!("buffers pod from_bytes: invalid");
                return;
            };
            if let Err(e) = stream.update_params(&mut [pod]) {
                eprintln!("update_params: {e}");
            }
        })
        .process(|stream, ud| {
            if ud.decoded {
                return;
            }
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let datas = buffer.datas_mut();
            if datas.is_empty() {
                return;
            }
            let n_planes = datas.len();
            let chunk_size = datas[0].chunk().size() as usize;
            let chunk_offset = datas[0].chunk().offset() as usize;
            let chunk_stride = datas[0].chunk().stride();
            let data_type = datas[0].type_();
            let Some(buf) = datas[0].data() else {
                return;
            };
            if !ud.diagnosed {
                ud.diagnosed = true;
                let mmap_len = buf.len();
                let head: Vec<u8> = buf[..mmap_len.min(16)].to_vec();
                println!(
                    "FIRST FRAME: planes={n_planes} data[0]: type={data_type:?} mmap_len={mmap_len} chunk(size={chunk_size}, offset={chunk_offset}, stride={chunk_stride}) head={head:02x?}"
                );
            }
            if chunk_size == 0 || chunk_offset + chunk_size > buf.len() {
                return;
            }
            let frame = &buf[chunk_offset..chunk_offset + chunk_size];
            let w = ud.format.size().width;
            let h = ud.format.size().height;
            if w == 0 || h == 0 {
                return;
            }

            let result = match ud.format.format() {
                spa::param::video::VideoFormat::RGBA
                | spa::param::video::VideoFormat::RGBx => qr::decode_rgba(w, h, frame),
                // YUY2 (== YUYV): Y0 Cb Y1 Cr (4 bytes per 2 pixels).
                // Y plane = every other byte starting at 0.
                spa::param::video::VideoFormat::YUY2 => {
                    let luma: Vec<u8> = frame.chunks_exact(2).map(|c| c[0]).collect();
                    qr::decode_grayscale(w, h, &luma)
                }
                // I420 (planar YUV 4:2:0): Y plane is the first w*h
                // bytes of the buffer (followed by U, V planes).
                spa::param::video::VideoFormat::I420 => {
                    let plane = (w as usize) * (h as usize);
                    if frame.len() < plane {
                        return;
                    }
                    qr::decode_grayscale(w, h, &frame[..plane])
                }
                f => {
                    eprintln!("Unsupported format: {:?}", f);
                    ud.decoded = true;
                    ud.mainloop.quit();
                    return;
                }
            };

            match result {
                Ok(payloads) => {
                    println!("DECODED {} payload(s):", payloads.len());
                    for p in &payloads {
                        println!("  {p}");
                    }
                    ud.decoded = true;
                    ud.mainloop.quit();
                }
                Err(qr::QrError::NoCodesFound) => {
                    // Quiet: typical for most frames. Hold the QR up.
                }
                Err(e) => {
                    eprintln!("decode err: {e}");
                }
            }
        })
        .register()?;

    // Format negotiation pod. Pin to YUY2 640x480 @ 30fps — the
    // camera tested with (OBSBOT Meet 2) exposes raw YUYV only at
    // 640x360 and 640x480 (anything larger is MJPG, which would
    // need on-the-fly JPEG decode per frame). 640x480 has
    // 76,800 luma samples — enormous overprovisioning for a QR.
    // Production camera.rs should broaden this; this is a spike.
    let format_pod = spa::pod::object!(
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
    );
    let pod_bytes: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(format_pod),
    )?
    .0
    .into_inner();
    let mut params = [Pod::from_bytes(&pod_bytes).expect("valid pod")];

    stream.connect(
        spa::utils::Direction::Input,
        target_node_id,
        pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;

    println!("Waiting for first QR decode... (Ctrl+C to abort)");
    mainloop.run();

    println!("Spike done.");
    Ok(())
}

/// Build the SPA_TYPE_OBJECT_ParamBuffers pod that tells the source
/// what buffer shape we accept. Without this the v4l2 source defaults
/// to DmaBuf, which our MAP_BUFFERS stream flag can't auto-mmap, and
/// the stream errors out on `use_buffers: -22`.
///
/// The libspa Rust crate doesn't expose a friendly enum for the
/// BUFFERS_* property keys, so we hand-build the Object with raw
/// `Property::new(spa_sys_const, Value::...)`.
fn build_buffers_pod(stride: i32, size: i32) -> spa::pod::Object {
    use pw::spa::pod::{ChoiceValue, Object, Property, Value};
    use pw::spa::utils::{Choice, ChoiceEnum, ChoiceFlags};

    let mempt_bit: i32 = 1 << pw::spa::sys::SPA_DATA_MemPtr;
    let memfd_bit: i32 = 1 << pw::spa::sys::SPA_DATA_MemFd;

    Object {
        type_: spa::utils::SpaTypes::ObjectParamBuffers.as_raw(),
        id: spa::param::ParamType::Buffers.as_raw(),
        properties: vec![
            // Number of buffers: prefer 8, accept 2..=32.
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
            // One contiguous block per buffer (no planar formats here).
            Property::new(pw::spa::sys::SPA_PARAM_BUFFERS_blocks, Value::Int(1)),
            // Frame size: stride * height bytes.
            Property::new(pw::spa::sys::SPA_PARAM_BUFFERS_size, Value::Int(size)),
            Property::new(pw::spa::sys::SPA_PARAM_BUFFERS_stride, Value::Int(stride)),
            // Accept MemPtr or MemFd data — both are mmap-friendly.
            // Not declaring DmaBuf keeps the MAP_BUFFERS flag honest.
            Property::new(
                pw::spa::sys::SPA_PARAM_BUFFERS_dataType,
                Value::Choice(ChoiceValue::Int(Choice::<i32>(
                    ChoiceFlags::empty(),
                    ChoiceEnum::<i32>::Flags {
                        default: mempt_bit | memfd_bit,
                        flags: vec![mempt_bit, memfd_bit],
                    },
                ))),
            ),
        ],
    }
}
