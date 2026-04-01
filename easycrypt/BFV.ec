require import AllCore List Distr DBool.
require import Primitives.

module type BFV_Scheme = {
  proc keygen ()                         : epk * esk
  proc enc    (pk : epk, v : vote)       : ciphertext
  proc dec    (sk : esk, c : ciphertext) : vote option
  proc add    (cs : ciphertext list)     : ciphertext
  proc rerand (pk : epk, c : ciphertext) : ciphertext
}.

module type BFV_INDCPA_ADV (S : BFV_Scheme) = {
  proc find  (pk : epk)          : vote * vote
  proc guess (c  : ciphertext)   : bool
}.

module BFV_INDCPA (BFV : BFV_Scheme) (A : BFV_INDCPA_ADV) = {
  proc main () : bool = {
    var pk : epk;
    var sk : esk;
    var v0 : vote;
    var v1 : vote;
    var c  : ciphertext;
    var b  : bool;
    var b' : bool;
    (pk, sk) <@ BFV.keygen ();
    (v0, v1) <@ A(BFV).find (pk);
    b        <$ dbool;
    c        <@ BFV.enc (pk, if b then v1 else v0);
    b'       <@ A(BFV).guess (c);
    return (b = b');
  }
}.
