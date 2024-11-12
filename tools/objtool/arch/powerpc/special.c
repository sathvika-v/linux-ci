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

static int is_le(struct objtool_file *file)
{
    return file->elf->ehdr.e_ident[EI_DATA] == ELFDATA2LSB;
}

static int is_64bit(struct objtool_file *file)
{
    return file->elf->ehdr.e_ident[EI_CLASS] == ELFCLASS64;
}

static uint32_t f32_to_cpu(struct objtool_file *file, uint32_t val)
{
    if (is_le(file))
        return __le32_to_cpu(val);
    else
        return __be32_to_cpu(val);
}

static uint64_t f64_to_cpu(struct objtool_file *file, uint64_t val)
{
    if (is_le(file))
        return __le64_to_cpu(val);
    else
        return __be64_to_cpu(val);
}

int process_fixup_entries(struct objtool_file *file)
{
	struct section *sec;
	unsigned int nr = 0;
	int i;

	for_each_sec(file, sec) {
		if (strstr(sec->name, "_ftr_fixup") != NULL) {
			Elf_Data *data = sec->data;

			printf("processing section: %s\n", sec->name);
			if (data && data->d_size > 0) {
				nr = data->d_size / sizeof(struct fixup_entry_64);

				for (i = 0; i < nr; i++) {
		
					unsigned long idx;
					unsigned long long off;
					struct fixup_entry_64 *dst;

					if (is_64bit(file)) {
						struct fixup_entry_64 *src;
						//struct fixup_entry_64 *dst;
						
						printf("is 64 bit\n");
						idx = i * sizeof(struct fixup_entry_64);
						off = sec->sh.sh_addr + data->d_off + idx;
						src = data->d_buf + idx;

						if (src->alt_start_off == src->alt_end_off)
							continue;

						fes = realloc(fes, (nr_fes + 1) * sizeof(struct fixup_entry));
						dst = &fes[nr_fes];
						nr_fes++;

						dst->mask = f64_to_cpu(file, src->mask);
						dst->value = f64_to_cpu(file, src->value);
						dst->start_off = f64_to_cpu(file, src->start_off) + off;
						dst->end_off = f64_to_cpu(file, src->end_off) + off;
						dst->alt_start_off = f64_to_cpu(file, src->alt_start_off) + off;
						dst->alt_end_off = f64_to_cpu(file, src->alt_end_off) + off;
                                                printf("off: 0x%llx\n", off);
                                                printf("dst->alt_start_off: 0x%lx, dst->alt_end_off: 0x%lx\n", dst->alt_start_off, dst->alt_end_off);
                                                printf("fe_alt_start: 0x%lx, fe_alt_end: 0x%lx\n", fe_alt_start, fe_alt_end);

					}
					
					else {
						struct fixup_entry_32 *src;
						//struct fixup_entry_64 *dst;

						printf("is 32 bit\n");
					
						idx = i * sizeof(struct fixup_entry_32);

						off = sec->sh.sh_addr + data->d_off + idx;
						src = data->d_buf + idx;

						if (src->alt_start_off == src->alt_end_off)
							continue;

						fes = realloc(fes, (nr_fes + 1) * sizeof(struct fixup_entry));
						dst = &fes[nr_fes];
						nr_fes++;

						dst->mask = f32_to_cpu(file, src->mask);
						dst->value = f32_to_cpu(file, src->value);
						dst->start_off = f32_to_cpu(file, src->start_off) + off;
						dst->end_off = f32_to_cpu(file, src->end_off) + off;
						dst->alt_start_off = f32_to_cpu(file, src->alt_start_off) + off;
						dst->alt_end_off = f32_to_cpu(file, src->alt_end_off) + off;
						
						printf("off: 0x%llx\n", off);
						printf("dst->alt_start_off: 0x%lx, dst->alt_end_off: 0x%lx\n", dst->alt_start_off, dst->alt_end_off);
						printf("fe_alt_start: 0x%lx, fe_alt_end: 0x%lx\n", fe_alt_start, fe_alt_end);
					}

					if (strstr(sec->name, ".rela") == NULL) {
						if (dst->alt_start_off < fe_alt_start)
							fe_alt_start = dst->alt_start_off;

						if (dst->alt_end_off > fe_alt_end)
							fe_alt_end = dst->alt_end_off;
					}
				

					printf("%llx fixup entry %llx:%llx (%llx-%llx) <- (%llx-%llx)\n", off,
					(unsigned long long)dst->mask, (unsigned long long)dst->value,
					(unsigned long long)dst->start_off, (unsigned long long)dst->end_off,
					(unsigned long long)dst->alt_start_off, (unsigned long long)dst->alt_end_off);
				}
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

	if (is_64bit(file))
		nr = data->d_size / sizeof(struct bug_entry_64);
	else
		nr = data->d_size / sizeof(struct bug_entry_32);

	for (i = 0; i < nr; i++) {
		unsigned long idx;
		uint64_t bugaddr;
		unsigned long long off;

		if (is_64bit(file)) {
			struct bug_entry_64 *bug;

			printf("process_bug_entries(): 64 bit\n");

			idx = i * sizeof(struct bug_entry_64);
			off = section->sh.sh_addr + data->d_off + idx;
			bug = data->d_buf + idx;
			bugaddr = (bug->bug_addr) + off;
	                printf("bugaddr[%d]: 0x%lx\n", i, bugaddr);
        	        printf("off: 0x%llx\n", off);
                	printf("fe_alt_start: 0x%lx\n", fe_alt_start);
                	printf("fe_alt_end: 0x%lx\n", fe_alt_end);
		}

		else {
			struct bug_entry_32 *bug;

			printf("process_bug_entries(): 32 bit\n");

			idx = i * sizeof(struct bug_entry_32);
			off = section->sh.sh_addr + data->d_off + idx;
			bug = data->d_buf + idx;
			bugaddr = (bug->bug_addr) + off;
                        printf("bugaddr[%d]: 0x%lx\n", i, bugaddr);
                        printf("off: 0x%llx\n", off);
                        printf("bugaddr[%d] + off: 0x%llx\n", i, bugaddr + off);
                        printf("fe_alt_start: 0x%lx\n", fe_alt_start);
                        printf("fe_alt_end: 0x%lx\n", fe_alt_end);

		}

/*
		printf("bugaddr[%d]: 0x%lx\n", i, bugaddr);
		printf("off: 0x%llx\n", off);
		printf("bugaddr[%d] + off: 0x%llx\n", i, bugaddr + off);
                printf("fe_alt_start: 0x%lx\n", fe_alt_start);
                printf("fe_alt_end: 0x%lx\n", fe_alt_end);
*/

		if (bugaddr < fe_alt_start)
			continue;

		if (bugaddr >= fe_alt_end)
			continue;

		printf("ftr_alt code contains a bug entry, which is not allowed. address=%llx\n", (unsigned long long)bugaddr);
		exit(EXIT_FAILURE);
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
			insn = f32_to_cpu(file, *i);

			printf("Instruction before modification: 0x%x\n", insn);

			opcode = insn >> 26;

			if (opcode == 16)
				set_cond_branch_target(&insn, dst_addr, target);

			if (opcode == 18)
				set_uncond_branch_target(&insn, dst_addr, target);

			printf("Instruction after modification: 0x%x\n", insn);
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

	if (is_64bit(file))
		nr = data->d_size / sizeof(struct exception_entry_64);
	else
		nr = data->d_size / sizeof(struct exception_entry_32);

	for (i = 0; i < nr; i++) {
		unsigned long idx;
		uint64_t exaddr;
		unsigned long long off;

		if (is_64bit(file)) {
			struct exception_entry_64 *ex;
			
			printf("process_exception_entries(): 64 bit\n");
			idx = i * sizeof(struct exception_entry_64);
			off = section->sh.sh_addr + data->d_off + idx;
			ex = data->d_buf + idx;
			exaddr = (ex->insn) + off;
	                printf("off: 0x%llx\n", off);
        	        printf("(ex->insn): 0x%x\n", (ex->insn));
                	printf("exaddr[%d]: 0x%lx\n", i, exaddr);
                	printf("fe_alt_start: 0x%lx\n", fe_alt_start);
                	printf("fe_alt_end: 0x%lx\n", fe_alt_end);

		}
		else {
			struct exception_entry_32 *ex;
			printf("process_exception_entries(): 32 bit\n");
			idx = i * sizeof(struct exception_entry_32);
			off = section->sh.sh_addr + data->d_off + idx;
			ex = data->d_buf + idx;
			exaddr = f32_to_cpu(file, ex->insn) + off;
			printf("off: 0x%llx\n", off);
                        printf("f32_to_cpu(file, ex->insn): 0x%x\n", f32_to_cpu(file, ex->insn));
                        printf("exaddr[%d]: 0x%lx\n", i, exaddr);
                        printf("fe_alt_start: 0x%lx\n", fe_alt_start);
                        printf("fe_alt_end: 0x%lx\n", fe_alt_end);
		}

/*
		printf("off: 0x%llx\n", off);
		printf("(ex->insn): 0x%x\n", (ex->insn));
		printf("exaddr[%d]: 0x%lx\n", i, exaddr);
		printf("fe_alt_start: 0x%lx\n", fe_alt_start);
		printf("fe_alt_end: 0x%lx\n", fe_alt_end);
*/

		if (exaddr < fe_alt_start)
			continue;
		if (exaddr >= fe_alt_end)
			continue;

		exit(EXIT_FAILURE);
	}

	return 0;
}
