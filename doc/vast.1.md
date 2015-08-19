# VAST 1 "@MAN_DATE@" @VERSION_MAJ_MIN@ "Visibility Across Space and Time"

NAME
----

`vast` -- interface to a VAST node

SYNOPSIS
--------

`vast` [*options*] *command* [*arguments*]

OVERVIEW
--------

VAST is a distributed platform for large-scale network forensics. Its modular
system architecture is exclusively implemented in terms of the actor model. In
this model, concurrent entities (actors) execute in parallel and
communicate asynchronously solely via message passing. Users spawn system
components as actors and connect them together to create a custom system
topology.

DESCRIPTION
-----------

The `vast` executable enables users to manage an ecosystem, such as creating
event sources and sinks for data import/export, issuing queries, or retrieving
statistics about system components.

The following key actors exist:

**NODE**
  The main VAST actor which accommodates all other actors and manages global
  state. Use vastd(1) to start a NODE.

**SOURCE**
  Generates events from a data source, such as packets from a network interface
  or log files.

**SINK**
  Receives events as the result of a query and displays them in specific output
  format, such as JSON, PCAP (for packets), or Bro logs.

**ARCHIVE**
  Compressed bulk storage of the all events.

**INDEX**
  Accelerates queries by constructing bitmap indexes over a subset of the event
  data.

**IMPORTER**
  Accepts events from SOURCEs, assigns them unique 64-bit IDs, and relays
  them to ARCHIVE and INDEX.

**EXPORTER**
  Accepts query expressions from users, asks INDEX for hits, takes them to
  ARCHIVE to extract candidates, and relays matching events to SINKs.
  them to ARCHIVE and INDEX.

OPTIONS
-------

The *options* in front of *command* control how to to connect to a node.

The following *options* are available:

`-d` *dir* [*.*]
  The directory for logs and state.

`-e` *endpoint* [*127.0.0.1:42000*]
  The endpoint of the node to connect to or launch. (See below)

`-l` *verbosity* [*3*]
  The logging verbosity. (See below)

`-h`
  Display a help message and exit.

`-v`
  Print VAST version and exit.

### endpoint

An endpoint has the format *host:port* where *host* is a hostname or IP address
and *port* the transport-layer port of the listening daemon. Either can be
omitted: *host* or *:port* are also valid endpoints. IPv6 addresses must be
enclosed in brackets in conjunction with a *port*, e.g., *[::1]:42001*.

### verbosity

The verbosity controls the amount of status messages displayed on console and
in log files. It can take on the following values:
    *0* *(quiet)*: do not produce any output
    *1* *(error)*: report failures which constitute a program error
    *2* *(warn)*: notable issues that do not affect correctness
    *3* *(info)*: status messages representing system activity
    *4* *(verbose)*: more fine-grained activity reports
    *5* *(debug)*: copious low-level implementation details
    *6* *(trace)*: log function entry and exit

COMMANDS
--------

This section describes each *command* and its *arguments*. The following
commands exist:
    *stop*          stops a node
    *peer*          peers with another node
    *show*          shows various properties of an ecosystem
    *spawn*         creates a new actor
    *quit*          terminates an actor
    *send*          send a message to an actor
    *connect*       connects two spawned actors
    *disconnect*    disconnects two connected actors
    *import*        imports data from standard input
    *export*        exports query results to standard output

### stop

Synopsis:

  *stop*

Stops the node and terminates all contained actors.

### peer

Synopsis:

  *peer* *endpoint*

Joins an ecosystem through a node identified by *endpoint*.
See **OPTIONS** for a description of the *endpoint* syntax.

### show

Synopsis:

  *show* *argument*

Shows various properties of an ecosystem. *argument* can have the
following values:

*nodes*
  Displays all existing nodes in the ecosystem.

*peers*
  Displays the nodes connected to this node.

*components*
  Displays the existing components per node.

*topology*
  Displays the connections between nodes.

### spawn

Synopsis:

  *spawn* [*arguments*] *actor* [*parameters*]

Creates a new actor of kind *actor*. Some actor types can have at most one
instance while others can have multiple instances.

Available *arguments*:

`-n` *name*
  Controls the spawn location. If `-n` *name* is given, the actor will be
  spawned on the node identified by *name*. Otherwise the actor will be
  spawned on the connected node.

`-l` *label*
   A unique identifier for *actor* within a node. The default label
   has the form *actorN* where *N* is a running counter increased for each
   spawned instance of *actor*.

Available *actor* values with corresponding *parameters*:

*archive* [*parameters*]
  `-c` *compression* [*lz4*]
    Compression algorithm for chunks
  `-s` *segments* [*10*]
    Number of cached segments
  `-m` *size* [*128*]
    Maximum segment size in MB

*index* [*parameters*]
  `-a` *partitions* [*5*]
    Number of active partitions to load-balance events over.
  `-p` *partitions* [*10*]
    Number of passive partitions.
  `-e` *events* [*1,048,576*]
    Maximum events per partition. When an active partition reaches its
    maximum, the index evicts it from memory and replaces it with an empty
    partition.

*importer*

*exporter* [*parameters*] *expression*
  `-a`
    Autoconnect to available archives and indexes on the node.
  `-c`
    Marks this exporter as *continuous*.
  `-h`
    Marks this exporter as *historical*.
  `-u`
    Marks this exporter as *unified*, which is equivalent to both
    `-c` and `-h`.
  `-e` *n* [*0*]
    The maximum number of events to extract; *n = 0* means unlimited.

*source* **X** [*parameters*]
  **X** specifies the format of *source*. Each source format has its own set of
  parameters, but the following parameters apply to all formats:
  `-a`
    Autoconnect to available importers on the node.
  `-b` *batch-size* [*100,000*]
    Number of events to read in one batch.

*source* *bro*
  `-r` *path*
    Name of the filesystem *path* (file or directory) to read events from.
  `-s` *schema*
    Path to an alterative *schema* file which overrides the default attributes.
  `-u` *uds*
    Treats `-r` as a listening UNIX domain socket instead of a regular file.

*source* *bgpdump*
  `-r` *path*
    Name of the file to read events from.
  `-s` *schema*
    Path to an alterative *schema* file which overrides the default attributes.
  `-u` *uds*
    Treats `-r` as a listening UNIX domain socket instead of a regular file.

*source* *test* [*parameters*]
  `-e` *events*
    The maximum number of *events* to generate.

*source* *pcap* [*parameters*]
  `-i` *interface*
    Name of the network *interface* to read packets from. (Overrides -r)
  `-c` *cutoff*
    The *cutoff* values specifies the maximum number of bytes to record per
    flow in each direction. That is, the maximum number of recorded bytes flow
    bytes can at most be twice as much as *cutoff*. the flow will be ignored
  `-f` *max-flows* [*1,000,000*]
    The maximum number of flows to track concurrently. When there exist more
    flows than *max-flows*, a new flow will cause eviction of a element from
    the flow table chosen uniformly at random.
  `-a` *max-age* [*60*]
    The maximum lifetime of a flow before it gets evicted from the flow table.
  `-p` *c*
    Enable pseudo-realtime mode by a factor of *1/c* to artificially delay
    packet processing when reading from trace files. This means that the PCAP
    source in that it sleeps for the amount of time observed in the packet
    timestamp differences. If the PCAP source encounters a packet *p1* after a
    previous packet *p0* with timestamps *t1* and *t0*, then it will sleep for
    time *(t1-t0)/c* before processing *p1*.
  `-r` *path*
    Filename of trace file to read packets from.
  `-s` *schema*
    Path to an alterative *schema* file which overrides the default attributes.

*sink* **X** [*parameters*]
  **X** specifies the format of *sink*. Each source format has its own set of
  parameters, but the following parameters apply to all formats:
  `-w` *path*
    Name of the filesystem *path* (file or directory) to write events to.

*sink* *ascii*
  `-u` *uds*
    Treats `-w` as a listening UNIX domain socket instead of a regular file.

*sink* *bro*

*sink* *json*
  `-u` *uds*
    Treats `-w` as a listening UNIX domain socket instead of a regular file.

*sink* *pcap* [*parameters*]
  `-f` *flush* [*1000*]
    Flush the output PCAP trace after having processed *flush* packets.

*profiler* [*parameters*]
  If compiled with gperftools, enables the gperftools CPU or heap profiler to
  collect samples at a given resolution.
  `-c`
    Launch the CPU profiler.
  `-h`
    Launch the heap profiler.
  `-r` *seconds* [*1*]
    The profiling resolution in seconds.

### quit

Synopsis:

  *quit* *name*

Terminates an actor. The argument *name* refers to an actor label.

### send

Synopsis:

  *run* *name* *message*

Sends a message to an actor. The argument *name* refers to the actor to run.
The argument *message* represents the data to send to the actor.

Available messages:

*run*
  Tells an actor to start operating. Most actors do not need to be told to run
  explicitly. Only actors having a multi-stage setup phase (e.g., sources and
  exporters) can be run explicitly: after spawning one connects them with other
  actors before they run in a fully operating state.

*flush*
  Tells an actor to flush its state to the file system.

### connect

Synopsis:

  *connect* *A* *B*

Connects two actors named *A* and *B* by registering *A* as source for *B* and
*B* as sink for *A*.

Both *A* and *B* can consist of a comma-separated lists of actor labels. That
is, if *A* consists of *n* list entries and *B* of *m*, then the number
created connections equals to the cross product *n * m*.

### disconnect

Synopsis:

  *disconnect* *A* *B*

Removes a previously established connection between *A* and *B*.

As in `connect`, Both *A* and *B* can consist of a comma-separated lists of
actor labels.

### import

Synopsis:

  *import* *format* [*spawn-arguments*]

Imports data on standard input and send it to locally running node. This
command is a shorthand for spawning a source, connecting it with an importer,
and associating standard input of the process invoking *import* with the input
stream of the spawned source.

Because *import* always reads from standard input, *-r file* has no effect.

### export

Synopsis:

  *export* [*arguments*] *expression*

Issues a query and exports results to standard output. This command is a
shorthand for spawning a exporter and sink, linking the two, and relaying the
resulting event stream arriving at the sink to standard output of the process
invoking *export*.

Because *export* always writes to standard output, *-w file* has no effect.

EXAMPLES
--------

Make the node at 10.0.0.1 peer with 10.0.0.2:

    vast -e 10.0.0.1 peer 10.0.0.2

Connect to a node running at 1.2.3.4 on port 31337 and show the
topology:

    vast -e 1.2.3.4:31337 show topology

Import Bro log files:

    zcat log.gz | vast import bro

Run a historical query, printed in ASCII, limited to at most 10 results:

    vast export ascii -h -e 10 :addr in 10.0.0.0/8

BUGS
----

If you encounter a bug or have suggestions for improvement, please file an
issue at https://github.com/mavam/vast/issues.

SEE ALSO
--------

vastd(1)

Visit https://github.com/mavam/vast for more information about VAST.
