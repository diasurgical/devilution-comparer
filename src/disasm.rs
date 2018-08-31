use std::any::Any;
use std::ffi::CStr;
use std::io::{Error as IoError, Write};
use std::os::raw::c_char;

use zydis::gen::*;
use zydis::{Buffer, Decoder, Formatter, ZydisResult};

use super::hexformat::*;

#[derive(Debug, Clone)]
pub struct DisasmOpts {
    pub print_adresses: bool,
    pub show_mem_disp: bool,
    pub show_imms: bool,
}

#[derive(Debug)]
pub enum DisasmError {
    IoError(IoError),
    ZydisError(ZydisStatusCode),
}

pub fn write_disasm(
    writer: &mut impl Write,
    bytes: &[u8],
    disasm_opts: &mut DisasmOpts,
    offset: u64,
) -> Result<(), DisasmError> {
    let mut buf = [0u8; 255];

    let mut formatter =
        Formatter::new(ZYDIS_FORMATTER_STYLE_INTEL).map_err(DisasmError::ZydisError)?;
    formatter
        .set_print_address(Box::new(format_addrs))
        .map_err(DisasmError::ZydisError)?;

    if !disasm_opts.show_mem_disp {
        formatter
            .set_print_displacement(Box::new(void_format_disp))
            .map_err(DisasmError::ZydisError)?;
    }

    if !disasm_opts.show_imms {
        formatter
            .set_print_immediate(Box::new(void_format_imms))
            .map_err(DisasmError::ZydisError)?;
    }

    let decoder = Decoder::new(ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32)
        .map_err(DisasmError::ZydisError)?;

    for (insn, ip) in decoder.instruction_iterator(bytes, offset) {
        formatter
            .format_instruction_raw(&insn, &mut buf, Some(disasm_opts))
            .map_err(DisasmError::ZydisError)?;

        let insn_str = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) }.to_string_lossy();

        if disasm_opts.print_adresses {
            writeln!(writer, "{:X}: {}", ip, insn_str).map_err(DisasmError::IoError)?;
        } else {
            writeln!(writer, "{}", insn_str).map_err(DisasmError::IoError)?;
        }
    }

    Ok(())
}

fn format_addrs(
    _: &Formatter,
    buf: &mut Buffer,
    insn: &ZydisDecodedInstruction,
    op: &ZydisDecodedOperand,
    _: u64,
    disasm_opts: Option<&mut Any>,
) -> ZydisResult<()> {
    let opts = disasm_opts.unwrap().downcast_ref::<DisasmOpts>().unwrap();
    match op.type_ {
        // memory address
        2 => {
            if opts.show_mem_disp {
                if insn.opcode == 0xFF && [2, 3].contains(&insn.raw.modrm.reg) {
                    buf.append("<indir_fn>")? // hide function call addresses, 0xFF /3 = CALL m16:32)
                } else {
                    buf.append(&format!("{:#X}", op.mem.disp.value))?
                }
            } else {
                buf.append("<indir_addr>")?
            }
        }
        // immediate address
        4 => match insn.opcode {
            0xE8 => buf.append("<imm_fn>")?, // hide function call addresses, 0xE8 = CALL rel32
            _ => {
                if op.imm.isRelative != 0 {
                    buf.append("$")?;
                } else {
                    buf.append("<imm_addr>")?;
                    return Ok(());
                }
                if op.imm.isSigned != 0 {
                    buf.append(&format!(
                        "{:+#X}",
                        CustomUpperHexFormat(*unsafe { op.imm.value.s.as_ref() })
                    ))?;
                } else {
                    buf.append(&format!("{:+#X}", unsafe { op.imm.value.u.as_ref() }))?;
                }
            }
        },
        _ => {}
    }

    Ok(())
}

fn void_format_disp(
    _: &Formatter,
    buf: &mut Buffer,
    _: &ZydisDecodedInstruction,
    op: &ZydisDecodedOperand,
    _: Option<&mut Any>,
) -> ZydisResult<()> {
    if op.mem.disp.value != 0 {
        // only write the displacement if it's actually displacing
        // not the case for something like `mov bl, [eax]`, i.e. `mov bl, [eax+0x0]`
        buf.append(if op.mem.disp.value < 0 { "-" } else { "+" })?;
        buf.append(&format!("<disp{}>", op.size))?;
    }
    Ok(())
}

fn void_format_imms(
    _: &Formatter,
    buf: &mut Buffer,
    _: &ZydisDecodedInstruction,
    op: &ZydisDecodedOperand,
    _: Option<&mut Any>,
) -> ZydisResult<()> {
    buf.append(&format!("<imm{}>", op.size))?;
    Ok(())
}
