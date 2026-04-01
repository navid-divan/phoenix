require import AllCore List Distr DBool FSet SmtMap.
require import Primitives BFV ZKP FHS Hash.

module type Tally_Sim = {
  proc simulate (pbb : PBB, r : result) : tally_proof
}.

module type Recover_Alg = {
  proc recover (bb bb0 bb1 : BB) : BB
}.

module type VS_Oracles = {
  proc vote_lr (id : voter_id, v0 : vote, v1 : vote) : unit
  proc board   ()                                     : PBB
  proc tally   ()                                     : result * tally_proof
  proc verify  (id : voter_id)                        : bool
}.

module type VS_ADV (O : VS_Oracles) = {
  proc a1 (voters : voter_id list) : BB
  proc a2 ()                       : bool
  proc a3 ()                       : bool
}.
