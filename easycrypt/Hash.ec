require import AllCore List Distr DBool.
require import Primitives.

module type Hash_Func = {
  proc hash (b : ballot) : hash_val
}.

module type CR_ADV (H : Hash_Func) = {
  proc find () : ballot * ballot
}.

module CR_Game (H : Hash_Func) (A : CR_ADV) = {
  proc main () : bool = {
    var b1 : ballot;
    var b2 : ballot;
    var h1 : hash_val;
    var h2 : hash_val;
    (b1, b2) <@ A(H).find ();
    h1       <@ H.hash (b1);
    h2       <@ H.hash (b2);
    return (h1 = h2 /\ b1 <> b2);
  }
}.
