require import AllCore List Distr FSet SmtMap.

type voter_id.
type vote.
type ciphertext.
type zkproof.
type fhs_sig.
type fhs_pk.
type fhs_sk.
type hash_val.
type epk.
type esk.
type result.
type tally_proof.
type pp.

type ballot     = voter_id * fhs_pk * ciphertext * zkproof * fhs_sig.
type pub_ballot = fhs_pk  * ciphertext * zkproof * fhs_sig * hash_val.
type BB         = ballot list.
type PBB        = pub_ballot list.

op b_id  (b : ballot) : voter_id = b.`1.
op b_upk (b : ballot) : fhs_pk   = b.`2.
op b_c   (b : ballot) : ciphertext = b.`3.
op b_pi  (b : ballot) : zkproof  = b.`4.
op b_sig (b : ballot) : fhs_sig  = b.`5.

op policy (bb : BB) : BB =
  foldr (fun (b : ballot) (acc : BB) =>
    if has (fun b' => b_id b' = b_id b) acc
    then acc
    else b :: acc)
  [] (rev bb).
