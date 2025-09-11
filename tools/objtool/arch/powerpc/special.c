// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>
#include <stdlib.h>
#include <objtool/special.h>
#include <objtool/builtin.h>
#include <objtool/warn.h>

struct section *ftr_alt;

uint64_t fe_alt_start = -1;
uint64_t fe_alt_end;

bool arch_support_alt_relocation(struct special_alt *special_alt,
				 struct instruction *insn,
				 struct reloc *reloc)
{
	exit(-1);
}

struct reloc *arch_find_switch_table(struct objtool_file *file,
				     struct instruction *insn,
				     unsigned long *table_size)
{
	exit(-1);
}

int process_alt_data( struct objtool_file* file)
{
	struct section *ftr_alt_section;

	ftr_alt_section = find_section_by_name(file->elf, ".__ftr_alternates.text");

	if (ftr_alt_section) {
		fe_alt_start = ftr_alt_section->sh.sh_addr;
		fe_alt_end = ftr_alt_section->sh.sh_addr + ftr_alt_section->sh.sh_size;
	}
	else {
		WARN(".__ftr_alternates.text section not found\n");
	}

	return 0;
}
	
