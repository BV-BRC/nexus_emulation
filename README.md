# Nexus Authentication Emulation Service

## Overview

This module implements a Globus Nexus authentication service that uses pluggable third party authentication providers to authenticate users. These providers include the RAST and SEED login services as well as the now-out-of-service VIPR authentication database.

## About this module

This module is a component of the BV-BRC build system. It is designed to fit into the
`dev_container` infrastructure which manages development and production deployment of
the components of the BV-BRC. More documentation is available [here](https://github.com/BV-BRC/dev_container/tree/master/README.md).

## References

Chard K, Lidman M, McCollam B, Bryan J, Ananthakrishnan R, Tuecke S, Foster I. Globus Nexus: A Platform-as-a-Service Provider of Research Identity, Profile, and Group Management. Future Gener Comput Syst. 2016 Mar 1;56:571-583. doi: 10.1016/j.future.2015.09.006. PMID: 26688598; PMCID: PMC4681010.
