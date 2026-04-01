require import AllCore List Distr DBool.
require import Primitives.

module type FHS_Scheme = {
  proc setup    ()                                                  : fhs_pk * fhs_sk
  proc keygen   (mpk : fhs_pk, id : voter_id)                      : fhs_pk
  proc sign     (sk : fhs_sk, upk : fhs_pk, id : voter_id,
                 c : ciphertext, pi : zkproof)                     : fhs_sig
  proc verify   (upk : fhs_pk, id : voter_id,
                 c : ciphertext, pi : zkproof, s : fhs_sig)        : bool
  proc hide     (upk : fhs_pk, c : ciphertext, pi : zkproof,
                 s : fhs_sig)                                       : fhs_sig
  proc fhs_sim  (sk : fhs_sk, upk : fhs_pk, id : voter_id,
                 c : ciphertext, pi : zkproof)                     : fhs_sig
}.

module type FHS_CH_ADV (F : FHS_Scheme) = {
  proc find  (upk : fhs_pk)  : ciphertext * zkproof * fhs_sig
  proc guess (s   : fhs_sig) : bool
}.

module FHS_CH_Game (FHS : FHS_Scheme) (A : FHS_CH_ADV) = {
  proc main (b : bool) : bool = {
    var mpk : fhs_pk;
    var msk : fhs_sk;
    var upk : fhs_pk;
    var id  : voter_id;
    var c   : ciphertext;
    var pi  : zkproof;
    var s   : fhs_sig;
    var s'  : fhs_sig;
    var b'  : bool;
    (mpk, msk) <@ FHS.setup ();
    id         <- witness;
    upk        <@ FHS.keygen (mpk, id);
    (c, pi, s) <@ A(FHS).find (upk);
    if (b) {
      s' <@ FHS.fhs_sim (msk, upk, id, c, pi);
    } else {
      s' <@ FHS.hide (upk, c, pi, s);
    }
    b' <@ A(FHS).guess (s');
    return b';
  }
}.
