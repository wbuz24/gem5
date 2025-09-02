# Efficient Secure Memory with an Extended PMP Table (ePMP)

Currently:
 - ePMP Table exists (empty copy of PMP table)
 - MEE access from within PMP functions (i.e. PMP access from MEE)
 - Encryption bit is currently never set (within gem5)

TODO:
 - 

## Memory Encryption Controller
An extended memory controller that sits behind the LLC (on-chip) 

Currently, the gem5 implementation has a Memory Encryption Engine 
(but no MC) - this will be corrected to be a Memory Controller (MC) 
that house a MEE.

## Metadata Cache
