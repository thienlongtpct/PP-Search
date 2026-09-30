# Threat model, output policy and leakage

## Security model

* **Two computation parties**, party 0 and party 1, executing MP-SPDZ
  `semi2k` (additive secret sharing over Z_(2^128), OT-based preprocessing).
* **Semi-honest adversary** that corrupts **at most one** computation party.
  The corrupted party follows the protocol but tries to learn more from its
  view.
* The computation parties **do not collude**. If both are corrupted, or both
  parties' state is exposed, every input can be reconstructed.
* Input owners (requester, stations) and the coordinator are authenticated
  principals. Privacy is protected against them. For correctness they are
  assumed to follow the protocol (see the limitations).

This implementation makes **no** claim of:

* security against malicious (actively deviating) computation parties;
* security against colluding computation parties;
* confidentiality of the requester's location from the selected station once
  it has been delivered, which is the purpose of the authorised output.

## Roles

| Role | Trust | May learn |
|---|---|---|
| Requester | owns `(A_x, A_y)` | acknowledgement or abort from each party |
| Station `i` | owns `(P_ix, P_iy, R_i)` | whether it was selected; if selected, the requester's encoded coordinates |
| Computation party `j` | semi-honest, non-colluding | its own shares, public parameters, the authorised selection (see below) |
| Coordinator / router | semi-honest; not trusted with location data | the public parameters it chose, match / no-match, the selected station ID, abort codes |

## What is public

Every participant may know the following:

* the session ID, the requester's *name* (certificate identity) and the
  input timeout;
* the horizon `D`;
* the set, count and IDs of participating stations;
* which input owners connected, and when;
* message counts and sizes, which are fixed per message type;
* the protocol step at which a session aborted, with its abort code.

The requester's name is part of the public session parameters because
the parties must authenticate the requester. An application that needs
requester anonymity towards the coordinator and the parties must use
pseudonymous requester certificates.

## Output policy

| Recipient | Receives | Mechanism |
|---|---|---|
| Coordinator | `match` and, if matched, `selected station ID` | Both parties open `(match, match·id)` to each other through MP-SPDZ's `SemiMC`, then each sends `SessionResult` over TLS; the coordinator checks that the two agree. |
| Both computation parties | the same `match` and `selected station ID` | They must know it to route the output. The parties learn exactly what the coordinator learns. |
| Selected station | the requester's exact encoded `(A_x, A_y)` | Each party sends *its own* additive share over the station's authenticated TLS connection, bound to the session ID and station ID. The station adds the shares mod 2^128, which is `semi2k`'s reconstruction (no MACs). |
| Other stations | `NoOutput`, and no coordinate shares | |
| Requester | nothing from the parties beyond acknowledgements | An application may have the coordinator relay the result. |
| No match | no coordinates to anyone | `NoOutput` to every station. |

Intermediate values stay secret-shared: distances `q_i`, eligibility bits,
comparison bits, binary-search bounds, existence bits and candidate masks. The
only values ever opened are:

1. the masked differences inside MP-SPDZ's Beaver multiplication and inside
   MP-SPDZ's comparison and truncation sub-protocols, which are uniformly
   masked by fresh correlated randomness;
2. the authorised `(match, match·id)`.

The coordinator only relays public parameters and receives the result. It
never receives shares; input and output shares travel on direct TLS
connections between owners and parties, so the router can neither see the
plaintext nor collect enough shares to reconstruct it.

## Leakage inherent in the authorised outputs

The outputs themselves reveal information, and this is by design:

* **The selected station** learns the requester's exact location. It also
  learns that no other eligible station was strictly closer; ties go to the
  smaller ID. Combined with public knowledge of other stations, this narrows
  the requester's options further.
* **The coordinator and both parties** learn the selected station ID. If
  station locations and radii are known to them, this places the requester
  inside that station's support disk, within `D`, and inside the region where
  that station is the nearest eligible one.
* **A no-match result** reveals that no participating station has the
  requester within both its support radius and `D`. With public station data,
  that excludes regions.
* **Repeated sessions** leak more, for example through different station
  subsets or horizons chosen by the coordinator. The requester provides fresh
  inputs for every session, and TLS prevents replaying its shares, but the
  application must control how often a requester is searched and against
  which station subsets.
* **Timing and traffic.** The protocol's control flow, number of rounds and
  message sizes do not depend on private data. A network observer who can see
  the parties' TLS connections to stations can still tell the selected station
  apart: it receives two `OutputShare` frames per party, while the others
  receive one shorter `NoOutput`. Hiding this would need padding and dummy
  traffic, which is not implemented.

## Limitations

* **Semi-honest only.** A computation party that deviates can corrupt the
  result, for example by selecting a different station, or send incorrect
  output shares. `semi2k` has no MACs, so such deviations are not detected.
* **No collusion resistance.** The two parties together reconstruct
  everything.
* **Input validation.** Owners check their own ranges before sharing, but the
  parties cannot check secret-shared inputs. A malicious station could submit
  out-of-range values, such as a coordinate outside the signed 32-bit domain.
  That breaks the comparison bounds and can let it win or disrupt the
  selection. A range proof or in-MPC range check would be needed against
  malicious input owners.
* **Coordinator trust for availability and scope.** The coordinator chooses
  `D` and the station set, and any authenticated participant can cause an
  abort (denial of service).
* **Fail-stop MPC errors.** A failure inside the MPC phase terminates the
  party process without output; a supervisor must restart it.
* **Test PKI only.** `scripts/provision_test_pki.py` generates every key on
  one machine and keeps the CA key in the output directory. In a deployment:
  * every principal generates its own key;
  * the CA key is kept offline;
  * revocation (CRL/OCSP) is added, which is not implemented here;
  * MP-SPDZ's `P0`/`P1` certificates are exchanged and pinned out of band.
* **Implementation side channels.** Neither MP-SPDZ nor this code has been
  audited for constant-time behaviour or other side channels.

## What the tests do and do not show

The process-level tests
(`tests/integration/test_processes.py`) check:

* functional correctness against a plaintext oracle;
* that no output share reaches a non-selected station;
* rejection of malformed, duplicate and unauthorised input;
* timeouts, disconnects and aborts;
* exact triple consumption and exhaustion;
* that both parties' executed operation counts equal the public plan for
  `(N, D)`, and are identical across sessions with the same `(N, D)` but
  different inputs (the unit tests additionally compare the full sequence of
  interactive operations and batch sizes against an all-zero input);
* the absence of a distinctive requester coordinate from party logs.

A code audit (`grep` for openings and reconstruction, and `nm` on the
deployed binary) shows that the only openings in production code are the ones
listed above.

**None of this is a cryptographic security proof.** Passing functional tests,
or finding no plaintext in a packet capture, does not show that the protocol
is secure. The security argument rests on MP-SPDZ's `semi2k` protocol under
the stated model, on the composition described in `docs/ARCHITECTURE.md`
(only uniformly masked values and the authorised outputs are opened), and on
TLS for the channels.
