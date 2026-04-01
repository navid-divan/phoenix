require import AllCore List Distr DBool FSet SmtMap.
require import Primitives BFV ZKP FHS Hash.

op pb_upk (pb : pub_ballot) : fhs_pk   = pb.`1.
op pb_c   (pb : pub_ballot) : ciphertext = pb.`2.
op pb_pi  (pb : pub_ballot) : zkproof   = pb.`3.
op pb_sig (pb : pub_ballot) : fhs_sig   = pb.`4.
op pb_h   (pb : pub_ballot) : hash_val  = pb.`5.

module Phoenix (BFV : BFV_Scheme) (ZKP : ZKP_Scheme)
               (FHS : FHS_Scheme) (H   : Hash_Func) = {

  var epk : epk
  var esk : esk
  var gpp : pp
  var mpk : fhs_pk
  var msk : fhs_sk

  proc setup () : unit = {
    var pk : epk;
    var sk : esk;
    var p  : pp;
    var fp : fhs_pk;
    var fs : fhs_sk;
    (pk, sk) <@ BFV.keygen ();
    p        <@ ZKP.setup ();
    (fp, fs) <@ FHS.setup ();
    epk <- pk;
    esk <- sk;
    gpp <- p;
    mpk <- fp;
    msk <- fs;
  }

  proc register (id : voter_id) : fhs_pk * fhs_sk = {
    var upk : fhs_pk;
    upk <@ FHS.keygen (mpk, id);
    return (upk, msk);
  }

  proc vote (id : voter_id, v : vote, upk : fhs_pk, usk : fhs_sk) : ballot = {
    var c  : ciphertext;
    var pi : zkproof;
    var s  : fhs_sig;
    c  <@ BFV.enc (epk, v);
    pi <@ ZKP.prove (gpp, c, v);
    s  <@ FHS.sign (usk, upk, id, c, pi);
    return (id, upk, c, pi, s);
  }

  proc valid (bb : BB, b : ballot) : bool = {
    var id  : voter_id;
    var upk : fhs_pk;
    var c   : ciphertext;
    var pi  : zkproof;
    var s   : fhs_sig;
    var e1  : bool;
    var e2  : bool;
    var e3  : bool;
    id  <- b_id  b;
    upk <- b_upk b;
    c   <- b_c   b;
    pi  <- b_pi  b;
    s   <- b_sig b;
    e1  <- all (fun (b' : ballot) =>
             (b_id b' = id  /\ b_upk b' = upk) \/
             (b_id b' <> id /\ b_upk b' <> upk)) bb;
    e2 <@ ZKP.verify (gpp, c, pi);
    e3 <@ FHS.verify (upk, id, c, pi, s);
    return (e1 /\ e2 /\ e3);
  }

  proc publish (bb : BB) : PBB = {
    var pbb : PBB;
    var rel : BB;
    var b   : ballot;
    var h   : hash_val;
    rel <- policy bb;
    pbb <- [];
    while (rel <> []) {
      b   <- head witness rel;
      rel <- behead rel;
      h   <@ H.hash (b);
      pbb <- pbb ++ [(b_upk b, b_c b, b_pi b, b_sig b, h)];
    }
    return pbb;
  }

  proc tally (bb : BB) : result * tally_proof = {
    var rel  : BB;
    var cts  : ciphertext list;
    var b    : ballot;
    var e1   : bool;
    var e2   : bool;
    var cagg : ciphertext;
    var r    : result;
    var pf   : tally_proof;
    var pbb  : PBB;
    rel <- policy bb;
    cts <- [];
    while (rel <> []) {
      b   <- head witness rel;
      rel <- behead rel;
      e1 <@ ZKP.verify (gpp, b_c b, b_pi b);
      e2 <@ FHS.verify (b_upk b, b_id b, b_c b, b_pi b, b_sig b);
      if (e1 /\ e2) {
        cts <- cts ++ [b_c b];
      }
    }
    cagg <@ BFV.add (cts);
    r    <- witness;
    pbb  <@ publish (bb);
    pf   <- witness;
    return (r, pf);
  }

  proc verify_tally (pbb : PBB, r : result, pf : tally_proof) : bool = {
    var ok : bool;
    ok <- witness;
    return ok;
  }

  proc verify_vote (b : ballot, pbb : PBB) : bool = {
    var h     : hash_val;
    var found : bool;
    h     <@ H.hash (b);
    found <- has (fun (pb : pub_ballot) => pb_h pb = h) pbb;
    return found;
  }
}.
