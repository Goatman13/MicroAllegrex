import sys

import idc
import ida_ua
import ida_ida
import ida_idp
import ida_funcs
import ida_allins
import ida_bytes
import ida_idaapi
import ida_loader
import ida_kernwin
import ida_typeinf
import ida_hexrays


class PSPIntrinsic(object):

	def __init__(self, cdg, name):
		self.cdg = cdg

		# call info, sort of like func_type_data_t()
		self.call_info = ida_hexrays.mcallinfo_t()
		self.call_info.cc = ida_typeinf.CM_CC_FASTCALL
		self.call_info.callee = ida_idaapi.BADADDR
		self.call_info.solid_args = 0
		self.call_info.role = ida_hexrays.ROLE_UNK
		self.call_info.flags = ida_hexrays.FCI_SPLOK | ida_hexrays.FCI_FINAL | ida_hexrays.FCI_PROP

		# the actual 'call' microcode insn
		self.call_insn = ida_hexrays.minsn_t(cdg.insn.ea)
		self.call_insn.opcode = ida_hexrays.m_call
		self.call_insn.l.make_helper(name)
		self.call_insn.d.t = ida_hexrays.mop_f
		self.call_insn.d.f = self.call_info

		# temp return type
		self.call_info.return_type = ida_typeinf.tinfo_t()
		self.call_insn.d.size = 0

	def set_return_reg(self, mreg, type_string):
		ret_tinfo = ida_typeinf.tinfo_t()
		ret_tinfo.get_named_type(None, type_string)
		return self.set_return_reg_type(mreg, ret_tinfo)

	def set_return_reg_basic(self, mreg, basic_type):
		ret_tinfo = ida_typeinf.tinfo_t(basic_type)
		return self.set_return_reg_type(mreg, ret_tinfo)

	def set_return_reg_type(self, mreg, ret_tinfo):
		self.call_info.return_type = ret_tinfo
		self.call_insn.d.size = ret_tinfo.get_size()

		self.mov_insn = ida_hexrays.minsn_t(self.cdg.insn.ea)
		self.mov_insn.opcode = ida_hexrays.m_mov
		self.mov_insn.l.t = ida_hexrays.mop_d
		self.mov_insn.l.d = self.call_insn
		self.mov_insn.l.size = self.call_insn.d.size
		self.mov_insn.d.t = ida_hexrays.mop_r
		self.mov_insn.d.r = mreg
		self.mov_insn.d.size = self.call_insn.d.size

		if ret_tinfo.is_decl_floating():
			self.mov_insn.set_fpinsn()

	def add_argument_reg(self, mreg, type_string):
		op_tinfo = ida_typeinf.tinfo_t()
		op_tinfo.get_named_type(None, type_string)
		return self.add_argument_reg_type(mreg, op_tinfo)

	def add_argument_reg_basic(self, mreg, basic_type):
		op_tinfo = ida_typeinf.tinfo_t(basic_type)
		return self.add_argument_reg_type(mreg, op_tinfo)

	def add_argument_reg_type(self, mreg, op_tinfo):
		call_arg = ida_hexrays.mcallarg_t()
		call_arg.t = ida_hexrays.mop_r
		call_arg.r = mreg
		call_arg.type = op_tinfo
		call_arg.size = op_tinfo.get_size()

		self.call_info.args.push_back(call_arg)
		self.call_info.solid_args += 1

	def add_argument_imm(self, value, basic_type):
		op_tinfo = ida_typeinf.tinfo_t(basic_type)

		mop_imm = ida_hexrays.mop_t()
		mop_imm.make_number(value, op_tinfo.get_size())
		
		call_arg = ida_hexrays.mcallarg_t()
		call_arg.make_number(value, op_tinfo.get_size())
		call_arg.type = op_tinfo

		self.call_info.args.push_back(call_arg)
		self.call_info.solid_args += 1

	def emit(self):
		self.cdg.mb.insert_into_block(self.mov_insn, self.cdg.mb.tail)


class PSPLifter(ida_hexrays.microcode_filter_t):

	def __init__(self):
		super(PSPLifter, self).__init__()
		self._psp_handlers = \
		{
			ida_allins.PSP_bitrev: self.bitrev,
			ida_allins.PSP_mfic:   self.mfic,
			#ida_allins.PSP_mtic:   self.mtic,
			ida_allins.PSP_max:    self._max,
			ida_allins.PSP_min:    self._min,
			ida_allins.PSP_wsbw:   self.wsbw,

		}

	def match(self, cdg):
		return cdg.insn.itype in self._psp_handlers

	def apply(self, cdg):
		return self._psp_handlers[cdg.insn.itype](cdg, cdg.insn)

	def install(self):
		ida_hexrays.install_microcode_filter(self, True)
		print("Installed MicroAllegrex: (%u instructions supported)" % len(self._psp_handlers))

	def remove(self):
		ida_hexrays.install_microcode_filter(self, False)

	#--------------------------------------------------------------------------
	# Instructions
	#--------------------------------------------------------------------------

	def bitrev(self, cdg, insn):
	
		opcode = ida_bytes.get_wide_dword(insn.ea)
		rt = (opcode >> 16) & 0x1F
		rd = (opcode >> 11) & 0x1F
		rt = ida_hexrays.reg2mreg(rt)
		rd = ida_hexrays.reg2mreg(rd)
		psp_intrinsic = PSPIntrinsic(cdg, "bitrev")
		psp_intrinsic.add_argument_reg_basic(rt, ida_typeinf.BTF_UINT32)
		psp_intrinsic.set_return_reg_basic(rd, ida_typeinf.BTF_UINT32)
		psp_intrinsic.emit()
		return ida_hexrays.MERR_OK

	def mfic(self, cdg, insn):

		opcode = ida_bytes.get_wide_dword(insn.ea)
		rt = (opcode >> 16) & 0x1F
		rt = ida_hexrays.reg2mreg(rt)
		psp_intrinsic = PSPIntrinsic(cdg, "getInterruptMask")
		psp_intrinsic.set_return_reg_basic(rt, ida_typeinf.BTF_UINT32)
		psp_intrinsic.emit()
		return ida_hexrays.MERR_OK

	#def mtic(self, cdg, insn):
	#
	#	rt = ida_hexrays.reg2mreg(insn.Op1.reg)
	#
	#	psp_intrinsic = PSPIntrinsic(cdg, "setInterruptMask")
	#	psp_intrinsic.add_argument_reg_basic(rt, ida_typeinf.BTF_UINT32)
	#	psp_intrinsic.emit()
	#	return ida_hexrays.MERR_OK

	def minmax(self, cdg, insn, funcName):

		opcode = ida_bytes.get_wide_dword(insn.ea)
		rs = (opcode >> 21) & 0x1F
		rt = (opcode >> 16) & 0x1F
		rd = (opcode >> 11) & 0x1F
		rs = ida_hexrays.reg2mreg(rs)
		rt = ida_hexrays.reg2mreg(rt)
		rd = ida_hexrays.reg2mreg(rd)
		psp_intrinsic = PSPIntrinsic(cdg, funcName)
		psp_intrinsic.add_argument_reg_basic(rs, ida_typeinf.BTF_INT32)
		psp_intrinsic.add_argument_reg_basic(rt, ida_typeinf.BTF_INT32)
		psp_intrinsic.set_return_reg_basic(rd, ida_typeinf.BTF_INT32)
		psp_intrinsic.emit()
		return ida_hexrays.MERR_OK

	def _max(self, cdg, insn):
		return self.minmax(cdg, insn, "std::max")

	def _min(self, cdg, insn):
		return self.minmax(cdg, insn, "std::min")

	def wsbw(self, cdg, insn):

		opcode = ida_bytes.get_wide_dword(insn.ea)
		rt = (opcode >> 16) & 0x1F
		rd = (opcode >> 11) & 0x1F
		rt = ida_hexrays.reg2mreg(rt)
		rd = ida_hexrays.reg2mreg(rd)

		psp_intrinsic = PSPIntrinsic(cdg, "byteswap32")
		psp_intrinsic.add_argument_reg_basic(rt, ida_typeinf.BTF_UINT32)
		psp_intrinsic.set_return_reg_basic(rd, ida_typeinf.BTF_UINT32)
		psp_intrinsic.emit()
		return ida_hexrays.MERR_OK

#-----------------------------------------------------------------------------
# Plugin
#-----------------------------------------------------------------------------

def PLUGIN_ENTRY():
	return MicroAllegrex()

class MicroAllegrex(ida_idaapi.plugin_t):

	flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
	comment = "Allegrex MIPS support for the Hex-Rays Mips Decompiler"
	help = ""
	wanted_name = "MicroAllegrex"
	wanted_hotkey = ""
	loaded = False

	def init(self):

		if not ida_ida.inf_get_procname() == 'psp':
			return ida_idaapi.PLUGIN_SKIP

		ida_loader.load_plugin("hexmips")
		assert ida_hexrays.init_hexrays_plugin(), "Missing HexMips Decompiler..."

		self.psp_lifter = PSPLifter()
		self.psp_lifter.install()
		sys.modules["__main__"].lifter = self.psp_lifter
		self.loaded = True
		return ida_idaapi.PLUGIN_KEEP

	def run(self, arg):
		ida_kernwin.warning("%s cannot be run as a script in IDA." % self.wanted_name)

	def term(self):

		if not self.loaded:
			return

		# hex-rays automatically cleans up decompiler hooks, so not much to do here...
		self.psp_lifter = None
