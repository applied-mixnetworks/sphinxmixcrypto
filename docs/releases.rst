Releases
========

No "release schedule" schedule.


v0.0.1
------
January 18th, 2017

  * first release; client and server operations for the Sphinx mix network cryptographic packet format
    implemented using Chacha20 and Blake2b.

v0.0.2
------
February 5th, 2017
  * work in progress

v0.0.3
------
February 10th, 2017
  * Added the SphinxHeader and SphinxBody types and partial API docs.

v0.0.4
------
  * amend the IMixPKI interface so that it has a getter and setter for
    the mapping: client ID -> network address
  * fix client SURB creation API and add ReplyBlock and ReplyBlockDecryptionToken types.
  * fix unit tests and hypothesis tests
