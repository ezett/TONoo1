# TONoo1: 1-out-of-N Oblivious Transfer

TONoo1 (say: to noone) is an implementation of the 1-out-of-N Oblivious Transfer
scheme [presented by T. Chou and C. Orlandi
(2015)](https://dx.doi.org/10.1007/978-3-319-22174-8_3) with some minor
improvments.

1-out-of-N Oblivious Transfer refers to a cryptographic primitive, which allows
a participant of the scheme (called the Receiver) to query a database (hold by
the Sender) for an entry without revealing, which entry has been
queried. The Receiver requests the entry by a specifically tailored database
index, so that the index effectively stays unknown to the Sender. The Sender
takes this tailored database index and encrypts all entries of the database in a
way, that only the one entry matching the tailored index will be decryptable by
the Receiver. All encrypted entries are sent to the Receiver, which picks the
entry of interest and decrypts it. All other encrypted entries will be of no use
to the Receiver.

This implementation utilises elliptic curve cryptography (ECC) and replaces all
modular arithmetics originally proposed by the authors T. Chou and C. Orlandi.
Furthermore, this library allows the usage of non-integer indexes, which is
useful, when the IDs of the database entries are not known to the
Receiver, but the entries can be indexed by other means, e.g., when the database
is a hashtable. It furthermore allows the concealment of all entry indices with
respect to the non-requested entries by the Receiver, so that the Receiver does
not learn any information about non-requested entries. Not even their database
indices.

**Warning**: This library has not been (independently) audited and should
**not** be used for productive applications.
