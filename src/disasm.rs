use std::any::Any;
use std::io::{Error as IoError, Write};

use zydis::{
    AddressWidth, Decoder, Formatter, FormatterBuffer, FormatterContext, FormatterStyle,
    MachineMode, OperandType, OutputBuffer, Result as ZydisResult, Status,
};

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
    ZydisError(Status),
}

pub fn write_disasm(
    writer: &mut impl Write,
    bytes: &[u8],
    disasm_opts: &mut DisasmOpts,
    offset: u64,
) -> Result<(), DisasmError> {
    let mut buf = [0u8; 255];
    let mut buf = OutputBuffer::new(&mut buf);

    let mut formatter = Formatter::new(FormatterStyle::INTEL).map_err(DisasmError::ZydisError)?;
    formatter
        .set_print_address_abs(Box::new(format_addrs))
        .map_err(DisasmError::ZydisError)?;

    if !disasm_opts.show_mem_disp {
        formatter
            .set_print_disp(Box::new(void_format_disp))
            .map_err(DisasmError::ZydisError)?;
    }

    if !disasm_opts.show_imms {
        formatter
            .set_print_imm(Box::new(void_format_imms))
            .map_err(DisasmError::ZydisError)?;
    }

    let decoder =
        Decoder::new(MachineMode::LEGACY_32, AddressWidth::_32).map_err(DisasmError::ZydisError)?;

    for (insn, ip) in decoder.instruction_iterator(bytes, offset) {
        formatter
            .format_instruction(&insn, &mut buf, Some(ip), Some(disasm_opts))
            .map_err(DisasmError::ZydisError)?;

        let insn_str = buf.as_str().expect("not utf8");

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
    buf: &mut FormatterBuffer,
    ctx: &mut FormatterContext,
    disasm_opts: Option<&mut dyn Any>,
) -> ZydisResult<()> {
    let opts = disasm_opts.unwrap().downcast_ref::<DisasmOpts>().unwrap();

    unsafe {
        let op = &*ctx.operand;
        let insn = &*ctx.instruction;

        match op.ty {
            OperandType::MEMORY => {
                if opts.show_mem_disp {
                    if insn.opcode == 0xFF && [2, 3].contains(&insn.raw.modrm_reg) {
                        buf.append_str("<indir_fn>")? // hide function call addresses, 0xFF /3 = CALL m16:32)
                    } else {
                        buf.append_str(&format!("{:#X}", op.mem.disp.displacement))?
                    }
                } else {
                    buf.append_str("<indir_addr>")?
                }
            }
            OperandType::IMMEDIATE => match insn.opcode {
                0xE8 => buf.append_str("<imm_fn>")?, // hide function call addresses, 0xE8 = CALL rel32
                _ => {
                    if op.imm.is_relative {
                        buf.append_str("$")?;
                    } else {
                        buf.append_str("<imm_addr>")?;
                        return Ok(());
                    }
                    if op.imm.is_signed {
                        buf.append_str(&format!(
                            "{:+#X}",
                            CustomUpperHexFormat(op.imm.value as i64)
                        ))?;
                    } else {
                        buf.append_str(&format!("{:+#X}", op.imm.value))?;
                    }
                }
            },
            _ => {}
        }
    }

    Ok(())
}

fn void_format_disp(
    _: &Formatter,
    buf: &mut FormatterBuffer,
    ctx: &mut FormatterContext,
    _: Option<&mut dyn Any>,
) -> ZydisResult<()> {
    unsafe {
        let op = &*ctx.operand;
        if op.mem.disp.has_displacement {
            // only write the displacement if it's actually displacing
            // not the case for something like `mov bl, [eax]`, i.e. `mov bl, [eax+0x0]`
            buf.append_str(if op.mem.disp.displacement < 0 {
                "-"
            } else {
                "+"
            })?;
            buf.append_str(&format!("<disp{}>", op.size))?;
        }
    }
    Ok(())
}

fn void_format_imms(
    _: &Formatter,
    buf: &mut FormatterBuffer,
    ctx: &mut FormatterContext,
    _: Option<&mut dyn Any>,
) -> ZydisResult<()> {
    unsafe {
        let op = &*ctx.operand;
        buf.append_str(&format!("<imm{}>", op.size))?;
    }
    Ok(())
}

trait Compat {
    fn append_str<S: AsRef<str> + ?Sized>(&mut self, s: &S) -> ZydisResult<()>;
}

impl Compat for FormatterBuffer {
    /// Compat function to not have to change all of the code above
    fn append_str<S: AsRef<str> + ?Sized>(&mut self, s: &S) -> ZydisResult<()> {
        self.get_string().expect("not utf8").append(s)
    }
}
