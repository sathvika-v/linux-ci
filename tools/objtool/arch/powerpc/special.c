// SPDX-License-Identifier: GPL-2.0-or-later
#include <string.h>
#include <stdlib.h>
#include <objtool/special.h>
#include <objtool/builtin.h>
#include <objtool/warn.h>
#include <asm/byteorder.h>
#include <errno.h>

struct section *ftr_alt;

struct fixup_entry *fes;
unsigned int nr_fes;

uint64_t fe_alt_start = -1;
uint64_t fe_alt_end;

bool arch_support_alt_relocation(struct special_alt *special_alt,
				 struct instruction *insn,
				 struct reloc *reloc)
{
	exit(-1);
}

struct reloc *arch_find_switch_table(struct objtool_file *file,
				    struct instruction *insn)
{
	exit(-1);
}

int process_alt_data(struct objtool_file *file)
{
	struct section *section;

	section = find_section_by_name(file->elf, ".__ftr_alternates.text");
	ftr_alt = section;

	if (!ftr_alt) {
		WARN(".__ftr_alternates.text section not found\n");
		return -1;
	}

	return 0;
}

int process_fixup_entries(struct objtool_file *file)
{
	struct section *sec;
	unsigned int nr = 0;
	int i;

	for_each_sec(file, sec) {
		if (strstr(sec->name, "_ftr_fixup") != NULL) {
			Elf_Data *data = sec->data;

			if (data && data->d_size > 0)
				nr = data->d_size / sizeof(struct fixup_entry);

			for (i = 0; i < nr; i++) {
				struct fixup_entry *dst;
				unsigned long idx;
				unsigned long long off;
				struct fixup_entry *src;

				idx = i * sizeof(struct fixup_entry);
				off = sec->sh.sh_addr + data->d_off + idx;
				src = data->d_buf + idx;

				if (src->alt_start_off == src->alt_end_off)
					continue;

				fes = realloc(fes, (nr_fes + 1) * sizeof(struct fixup_entry));
				dst = &fes[nr_fes];
				nr_fes++;

				dst->mask = __le64_to_cpu(src->mask);
				dst->value = __le64_to_cpu(src->value);
				dst->start_off = __le64_to_cpu(src->start_off) + off;
				dst->end_off = __le64_to_cpu(src->end_off) + off;
				dst->alt_start_off = __le64_to_cpu(src->alt_start_off) + off;
				dst->alt_end_off = __le64_to_cpu(src->alt_end_off) + off;

				if (dst->alt_start_off < fe_alt_start)
					fe_alt_start = dst->alt_start_off;

				if (dst->alt_end_off > fe_alt_end)
					fe_alt_end = dst->alt_end_off;
			}
		}
	}

	return 0;
}

struct fixup_entry *find_fe_altaddr(uint64_t addr)
{
	unsigned int i;

	if (addr < fe_alt_start)
		return NULL;
	if (addr >= fe_alt_end)
		return NULL;

	for (i = 0; i < nr_fes; i++) {
		if (addr >= fes[i].alt_start_off && addr < fes[i].alt_end_off)
			return &fes[i];
	}
	return NULL;
}

int set_uncond_branch_target(uint32_t *insn,
	       const uint64_t addr, uint64_t target)
{
	uint32_t i = *insn;
	int64_t offset;

	offset = target;
	if (!(i & BRANCH_ABSOLUTE))
		offset = offset - addr;

	/* Check we can represent the target in the instruction format */
	if (offset < -0x2000000 || offset > 0x1fffffc || offset & 0x3)
		return -EOVERFLOW;

	/* Mask out the flags and target, so they don't step on each other. */
	*insn = 0x48000000 | (i & 0x3) | (offset & 0x03FFFFFC);

	return 0;
}

int set_cond_branch_target(uint32_t *insn,
	       const uint64_t addr, uint64_t target)
{
	uint32_t i = *insn;
	int64_t offset;

	offset = target;

	if (!(i & BRANCH_ABSOLUTE))
		offset = offset - addr;

	/* Check we can represent the target in the instruction format */
	if (offset < -0x8000 || offset > 0x7FFF || offset & 0x3) {
		printf("cannot represent\n");
		return -EOVERFLOW;
	}

	/* Mask out the flags and target, so they don't step on each other. */
	*insn = 0x40000000 | (i & 0x3FF0003) | (offset & 0xFFFC);

	return 0;
}

void check_and_flatten_fixup_entries(void)
{
	static struct fixup_entry *fe;
	unsigned int i;

	i = nr_fes;
	while (i) {
		static struct fixup_entry *parent;
		uint64_t nested_off; /* offset from start of parent */
		uint64_t size;

		i--;
		fe = &fes[i];

		parent = find_fe_altaddr(fe->start_off);
		if (!parent) {
			parent = find_fe_altaddr(fe->end_off);
			continue;
		}

		size = fe->end_off - fe->start_off;
		nested_off = fe->start_off - parent->alt_start_off;

		fe->start_off = parent->start_off + nested_off;
		fe->end_off = fe->start_off + size;
	}
}

int process_bug_entries(struct objtool_file *file)
{
	struct section *section;

	Elf_Data *data;
	unsigned int nr, i;

	section = find_section_by_name(file->elf, "__bug_table");

	data = section->data;

	nr = data->d_size / sizeof(struct bug_entry_64);

	for (i = 0; i < nr; i++) {
		unsigned long idx;
		uint64_t bugaddr;
		struct bug_entry_64 *bug;

		idx = i * sizeof(struct bug_entry_64);
		bug = data->d_buf + idx;
		bugaddr = __le64_to_cpu(bug->bug_addr);

		if (bugaddr < fe_alt_start)
			continue;

		if (bugaddr >= fe_alt_end)
			continue;
	}

	return 0;
}

static struct symbol *find_symbol_at_address_within_section(struct section *sec,
								unsigned long address)
{
	struct symbol *sym;

	sec_for_each_sym(sec, sym) {
		if (sym->sym.st_value <= address && address < sym->sym.st_value + sym->len)
			return sym;
	}

	return NULL;
}

static int is_local_symbol(uint8_t st_other)
{
	return (st_other & 0x3) != 0;
}

static struct symbol *find_symbol_at_address(struct objtool_file *file,
						unsigned long address)
{
	struct section *sec;
	struct symbol *sym;

	list_for_each_entry(sec, &file->elf->sections, list) {
		sym = find_symbol_at_address_within_section(sec, address);
		if (sym)
			return sym;
	}
	return NULL;
}

int process_alt_relocations(struct objtool_file *file)
{
	struct section *section;
	size_t n = 0;
	uint32_t insn;
	uint32_t *i;
	unsigned int opcode;

	section = find_section_by_name(file->elf, ".rela.__ftr_alternates.text");
	if (!section) {
		printf(".rela.__ftr_alternates.text section not found.\n");
		return -1;
	}

	for (int j = 0; j < sec_num_entries(section); j++) {
		struct reloc *relocation = &section->relocs[j];
		struct symbol *sym = relocation->sym;
		struct fixup_entry *fe;
		uint64_t addr = reloc_offset(relocation);
		uint64_t scn_delta;
		uint64_t dst_addr;
		const char *insn_ptr;
		unsigned long target = sym->sym.st_value + reloc_addend(relocation);

		struct symbol *symbol = find_symbol_at_address(file, target);

		if (symbol) {
			int is_local = is_local_symbol(symbol->sym.st_other);

			if (!is_local)
				target = target + 0x8;
		}

		n++;

		fe = find_fe_altaddr(addr);
		if (fe) {

			if (target >= fe->alt_start_off &&
					target < fe->alt_end_off)
				continue;

			if (target >= ftr_alt->sh.sh_addr &&
					target < ftr_alt->sh.sh_addr +
					ftr_alt->sh.sh_size) {
				printf("ftr_alt branch target is another ftr_alt region.\n");
				exit(EXIT_FAILURE);
			}

			scn_delta = addr - ftr_alt->sh.sh_addr;
			dst_addr = addr - fe->alt_start_off + fe->start_off;

			i = ftr_alt->data->d_buf + scn_delta;
			insn = __le32_to_cpu(*i);

			opcode = insn >> 26;

			if (opcode == 16)
				set_cond_branch_target(&insn, dst_addr, target);

			if (opcode == 18)
				set_uncond_branch_target(&insn, dst_addr, target);

			insn_ptr = (const char *)&insn;
			elf_write_insn(file->elf, ftr_alt, scn_delta, sizeof(insn), insn_ptr);
		}
	}

	return 0;
}

int process_exception_entries(struct objtool_file *file)
{
	struct section *section;
	Elf_Data *data;
	unsigned int nr, i;

	section = find_section_by_name(file->elf, "__ex_table");

	data = section->data;
	nr = data->d_size / sizeof(struct exception_entry_64);

	for (i = 0; i < nr; i++) {
		unsigned long idx;
		uint64_t exaddr;
		unsigned long long off;
		struct exception_entry_64 *ex;

		idx = i * sizeof(struct exception_entry_64);
		off = section->sh.sh_addr + data->d_off + idx;
		ex = data->d_buf + idx;
		exaddr = __le32_to_cpu(ex->insn) + off;

		if (exaddr < fe_alt_start)
			continue;
		if (exaddr >= fe_alt_end)
			continue;

		exit(EXIT_FAILURE);
	}

	return 0;
}
