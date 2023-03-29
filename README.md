# humpty

humpty: Hubris/Humility dump manipulation

This is a no_std crate that allows for dumping the system or some number
of tasks to a specified region of memory.  This crate is used by several
different consumers across several different domains, and is used by both
Hubris and Humility.

Our nomenclature:

- *Dump area*:  a contiguous area of RAM within Hubris that holds all or
  part of a dump.  This is an area of RAM that is not otherwise used by
  the system and (obviously?) shouldn't itself be dumped.

- *Dump contents*:  the contents of a dump area, and can be either a task
  (or part of a task) or the entire system (or part of it).  If an area is
  used for part of the system, all dump areas are used to dump the system.
  (That is, task dumps cannot be interspersed with system dumps.)

- *Dump segment header*:  a header describing a contiguous region of memory
  to be written into a dump.  These are added to a dump area via
  [`add_dump_segment_header`].

- *Dump segment*:  the actual data itself in a dump.  This can have the form
  of data (always compressed), or some limited metadata (registers and
  task information, if any).  If there is both metadata and data, the
  metadata will always precede the data.

- *Dump agent proxy*.  The body of software that creates dump areas and
  doles them out to dump agents.

- *Dump agent*. The software that claims a dump area from the dump agent
  proxy for the purpose of arranging dumping into it.

- *Dumper*.  The body of software that actually performs the dumping:
  knowing only the address of a dump area, it will dump contents into dump
  areas such as they are available.  (Jefe, the dedicated dumper task, and
  Humility in its emulation modes can all act as the dumper.)

In Hubris, Jefe always acts as the dump agent proxy.  In the case of task
dumps, Jefe also serves as the dump agent and the dumper (via kernel
facilities to read task memory).  For system dumps, the dedicated dump
agent serves as the agent, and an outside system (either Humility in its
emulation modes or a disjoint microcontroller running Hubris and connected
via SWD) acts as the dumper.

Regardless of which bodies are playing which part, the flow is:

 1. Dump agent asks dump agent proxy to claim an area on its behalf.

 2. Dump agent adds segment headers to describe the data to be dumped.

 3. Dumper calls [`dump`] to actually do the dumping.  [`dump`] will
    read and write to memory via the passed closures.

 4. Dump is retrieved by Humility for decompressing and processing.

