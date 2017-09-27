#!/usr/sbin/dtrace -s

#pragma D option quiet

string gTarget;     /* the name of the target executable */
int target_time;
/* print header */
dtrace:::BEGIN
{
gTarget = $$1;  /* get the target execname from 1st DTrace parameter */
	printf("Tracing %-16s Hit Ctrl-C to end.\n", $$1);
}

sched:::off-cpu
/execname == $$1/
{ self->ts = timestamp; }


sched:::on-cpu
/self->ts/
{
    @offcpu[execname] = sum(timestamp - self->ts); self->ts = 0;
    }


syscall::close*:entry, syscall::open*:entry, syscall::read*:entry, syscall::write*:entry
/execname == $$1/
{
self->start = timestamp;
}

/*
* capture target launch (success)
*/
proc:::exec-success
/
    gTarget == execname
/
{
    gTargetPID = pid;
    printf("detected target launch %-16s\n",execname);
    self->exec_sucess = timestamp;
}

/*
*   detect when our target exits
*/
syscall::*exit:entry
/
    pid == gTargetPID
/
{
printf("detected target exited %-16s\n",execname);
    gTargetPID = -1;        /* invalidate target pid */
    target_time = timestamp - self->exec_sucess / 1000;
}

syscall::close*:return, syscall::open*:return, syscall::read*:return, syscall::write*:return
/self->start/
{
	this->elapsed = timestamp - self->start;
	@files[pid, execname] = sum(this->elapsed);
	self->start = 0;
}

/* print report */
dtrace:::END
{
printf("target time %8d\n",  target_time );

normalize(@offcpu, 1000);
printf("%6s %8s\n", "CMD", "TIME");
printa("%-12s %@8d\n", @offcpu);

	normalize(@files, 1000);
	printf("%6s %-12s %8s\n", "PID", "CMD", "TIME");
	printa("%6d %-12.12s %@8d\n", @files);
}
