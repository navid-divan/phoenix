require import AllCore List Distr DBool.
require import Primitives.

module type ZKP_Scheme = {
  proc setup    ()                                      : pp
  proc prove    (p : pp, c : ciphertext, v : vote)     : zkproof
  proc verify   (p : pp, c : ciphertext, pi : zkproof) : bool
  proc zkp_sim  (p : pp, c : ciphertext)               : zkproof
}.

module type ZK_ADV (Z : ZKP_Scheme) = {
  proc find  (p : pp)         : ciphertext * vote
  proc guess (pi : zkproof)   : bool
}.

module ZK_Game (ZKP : ZKP_Scheme) (A : ZK_ADV) = {
  proc main (b : bool) : bool = {
    var p  : pp;
    var c  : ciphertext;
    var v  : vote;
    var pi : zkproof;
    var b' : bool;
    p      <@ ZKP.setup ();
    (c, v) <@ A(ZKP).find (p);
    if (b) {
      pi <@ ZKP.zkp_sim (p, c);
    } else {
      pi <@ ZKP.prove (p, c, v);
    }
    b' <@ A(ZKP).guess (pi);
    return b';
  }
}.
