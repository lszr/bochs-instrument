// SOF
/////////////////////////////////////////////////////////////////////////
// $Id$
/////////////////////////////////////////////////////////////////////////
//
//   Copyright (c) 2006-2015 Stanislav Shwartsman
//          Written by Stanislav Shwartsman [sshwarts at sourceforge net]
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

#include <assert.h>

#include "bochs.h"
#include "cpu/cpu.h"
#include "disasm/disasm.h"

// maximum size of an instruction
#define MAX_OPCODE_LENGTH 16

// maximum physical addresses an instruction can generate
#define MAX_DATA_ACCESSES 1024

// maximum buffer string size for displaying memory content, R or W
#define MAX_STRBUF 64

// Use this variable to turn on/off collection of instrumentation data
// If you are not using the debugger to turn this on/off, then possibly
// start this at 1 instead of 0.
static bx_bool active = 1;

static disassembler bx_disassembler;

static struct instruction_t {
  bx_bool  ready;         // is current instruction ready to be printed
  unsigned opcode_length;
  Bit8u    opcode[MAX_OPCODE_LENGTH];
  bx_bool  is32, is64;
  unsigned num_data_accesses;
  struct {
    bx_address laddr;     // linear address
    bx_phy_address paddr; // physical address
    unsigned rw;          // BX_READ, BX_WRITE or BX_RW
    unsigned size;        // 1 .. 64
    unsigned memtype;
  } data_access[MAX_DATA_ACCESSES];
  bx_bool is_branch;
  bx_bool is_taken;
  bx_address target_linear;
} *instruction;

static logfunctions *instrument_log = new logfunctions ();
#define LOG_THIS instrument_log->

static bx_address local_eip, opaddr, memacaddr;
static FILE *stdlog;
static bool showlog, beginreached, reached7c00, showint;

void bx_instr_init_env(void) {
  stdlog = fopen( "stdlog.txt", "wb" );
  showlog = false;
  beginreached = false;
  reached7c00 = false;
  showint = false;
}

void bx_instr_exit_env(void) {
  if( stdlog ) {
    fclose( stdlog );
  }
}

void bx_instr_initialize(unsigned cpu)
{
  assert(cpu < BX_SMP_PROCESSORS);

  if (instruction == NULL)
      instruction = new struct instruction_t[BX_SMP_PROCESSORS];

  fprintf(stdlog, "Initialize cpu %u\n", cpu);
}

void bx_instr_reset(unsigned cpu, unsigned type)
{
  instruction[cpu].ready = 0;
  instruction[cpu].num_data_accesses = 0;
  instruction[cpu].is_branch = 0;
}

void bx_print_instruction(unsigned cpu, const instruction_t *i, const bx_address eip)
{
  char disasm_tbuf[512];	// buffer for instruction disassembly
  char strbuf[MAX_STRBUF]; // buffer for displaying memory R/W content
  unsigned length = i->opcode_length, n, m;
  bx_disassembler.disasm(i->is32, i->is64, 0, 0, i->opcode, disasm_tbuf);

  // BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value, EIP);
  //unsigned int last_print;

  if(length != 0)
  {
    Bit8u *buf;
    Bit8u buffet[256];
    buf = &buffet[0];
    opaddr = BX_CPU(cpu)->get_laddr32(BX_SEG_REG_CS, local_eip);
    // Start at 7c00, do not log before
    if( (reached7c00==false) && (opaddr == 0x7c00) ) {
      fprintf( stdlog, "REACHED 7c00\n");
      reached7c00 = true;
    }
    // Decode stuff and jump to push series at 0x10000
    // End at 0x1412b
    if( (beginreached == false) && (reached7c00 == true) && (opaddr == 0x1412b) ) {
      fprintf( stdlog, "REACHED 0x1412b\n");
      showlog = true;
      beginreached = true;
    }
    // Check if we display
    if( (showlog==true) && (beginreached==true) && (opaddr == 0x15ac1) ) {
      fprintf( stdlog, "REACHED 0x15ac1\n");
      fflush( stdlog );
      showlog = false;
    }
    // target_linear = BX_CPU(cpu_id)->get_laddr(BX_SEG_REG_CS, new_eip);
    // BX_SMF Bit32u get_laddr32(unsigned seg, Bit32u offset);
    if( (showlog == true) && (opaddr < 0xc0000) ) {
      // Don't display retf
      if( strstr(disasm_tbuf,"retf") == NULL ) {
        fprintf( stdlog, "%x %s\n", opaddr, disasm_tbuf);
      }
      // Maybe show iret intruction
      if( (strstr(disasm_tbuf,"iret") !=NULL) && (showint==true) ) {
        fprintf( stdlog, "%x %s\n", opaddr, disasm_tbuf);
      }
      // Print address, hex values and characters
      for(n=0;n < i->num_data_accesses;n++)
      {
        memacaddr = i->data_access[n].paddr;
        //if( (memacaddr >= 0x1e700) && (memacaddr <= 0x1e7ff) ) {
        if( (memacaddr >= 0x10000) && (memacaddr <= 0x1ffff) ) {
          fprintf(stdlog, "%s%02d %x:",i->data_access[n].rw == BX_READ ? "RD":"WR", i->data_access[n].size, i->data_access[n].paddr );
          BX_MEM(0)->dbg_fetch_mem(BX_CPU(dbg_cpu), i->data_access[n].paddr, i->data_access[n].size, buf);
          for( m=0; m<i->data_access[n].size; ++m)
          {
              if( i->data_access[n].size == 1 ) {
                (void)fprintf( stdlog, "   " );
              }
              (void)fprintf(stdlog," %02x", buf[m]);
            if( buf[m]>=32 and buf[m]<126 and m<(MAX_STRBUF-1) )
            {
              strbuf[m] = buf[m];
            }
            else
            {
              strbuf[m] = '.';
            }
          }
          strbuf[m] = 0;
          (void)fprintf( stdlog, " >%s<\n", strbuf );
        }
      }
    }
/*
    fprintf(stdlog, "\n");
    fprintf(stdlog, "LEN %u\tBYTES: ", length);
    for(n=0;n < length;n++) fprintf(stdlog, "%02x", i->opcode[n]);
    if(i->is_branch)
    {
      fprintf(stdlog, "\tBRANCH ");

      if(i->is_taken)
        fprintf(stdlog, "TARGET " FMT_ADDRX " (TAKEN)", i->target_linear);
      else
        fprintf(stdlog, "(NOT TAKEN)");
    }
    fprintf(stdlog, "\n");
    for(n=0;n < i->num_data_accesses;n++)
    {
      fprintf(stdlog, "MEM ACCESS[%u]: 0x" FMT_ADDRX " (linear) 0x" FMT_PHY_ADDRX " (physical) %s SIZE: %d\n", n,
                    i->data_access[n].laddr,
                    i->data_access[n].paddr,
                    i->data_access[n].rw == BX_READ ? "RD":"WR",
                    i->data_access[n].size);
    }
    fprintf(stdlog, "\n");
*/
  }
}

void bx_instr_before_execution(unsigned cpu, bxInstruction_c *bx_instr, bx_address eip )
{
  if (!active) return;

  instruction_t *i = &instruction[cpu];

  local_eip = eip;
  if (i->ready) bx_print_instruction(cpu, i, eip);

  // prepare instruction_t structure for new instruction
  i->ready = 1;
  i->num_data_accesses = 0;
  i->is_branch = 0;

  i->is32 = BX_CPU(cpu)->sregs[BX_SEG_REG_CS].cache.u.segment.d_b;
  i->is64 = BX_CPU(cpu)->long64_mode();
  i->opcode_length = bx_instr->ilen();
  memcpy(i->opcode, bx_instr->get_opcode_bytes(), i->opcode_length);
}

void bx_instr_after_execution(unsigned cpu, bxInstruction_c *bx_instr, bx_address eip )
{
  if (!active) return;

  instruction_t *i = &instruction[cpu];
  if (i->ready) {
    bx_print_instruction(cpu, i, eip);
    i->ready = 0;
  }
}

static void branch_taken(unsigned cpu, bx_address new_eip)
{
  if (!active || !instruction[cpu].ready) return;

  instruction[cpu].is_branch = 1;
  instruction[cpu].is_taken = 1;

  // find linear address
  instruction[cpu].target_linear = BX_CPU(cpu)->get_laddr(BX_SEG_REG_CS, new_eip);
}

void bx_instr_cnear_branch_taken(unsigned cpu, bx_address branch_eip, bx_address new_eip)
{
  branch_taken(cpu, new_eip);
}

void bx_instr_cnear_branch_not_taken(unsigned cpu, bx_address branch_eip)
{
  if (!active || !instruction[cpu].ready) return;

  instruction[cpu].is_branch = 1;
  instruction[cpu].is_taken = 0;
}

void bx_instr_ucnear_branch(unsigned cpu, unsigned what, bx_address branch_eip, bx_address new_eip)
{
  branch_taken(cpu, new_eip);
}

void bx_instr_far_branch(unsigned cpu, unsigned what, Bit16u prev_cs, bx_address prev_eip, Bit16u new_cs, bx_address new_eip)
{
  branch_taken(cpu, new_eip);
}

void bx_instr_interrupt(unsigned cpu, unsigned vector)
{
  if(active && beginreached && showint)
  {
    fprintf(stdlog, "CPU %u: interrupt %02xh\n", cpu, vector);
  }
}

void bx_instr_exception(unsigned cpu, unsigned vector, unsigned error_code)
{
  if(active && beginreached && showint)
  {
    fprintf(stdlog, "CPU %u: exception %02xh, error_code = %x\n", cpu, vector, error_code);
  }
}

void bx_instr_hwinterrupt(unsigned cpu, unsigned vector, Bit16u cs, bx_address eip)
{
  if(active && beginreached && showint)
  {
    fprintf(stdlog, "CPU %u: hardware interrupt %02xh\n", cpu, vector);
  }
}

void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_phy_address phy, unsigned len, unsigned memtype, unsigned rw)
{
  if(!active || !instruction[cpu].ready) return;

  unsigned index = instruction[cpu].num_data_accesses;

  if (index < MAX_DATA_ACCESSES) {
    instruction[cpu].data_access[index].laddr = lin;
    instruction[cpu].data_access[index].paddr = phy;
    instruction[cpu].data_access[index].rw    = rw;
    instruction[cpu].data_access[index].size  = len;
    instruction[cpu].data_access[index].memtype = memtype;
    instruction[cpu].num_data_accesses++;
    index++;
  }
}
// EOF
