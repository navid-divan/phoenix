require import AllCore List Distr DBool FSet SmtMap.
require import Primitives BFV ZKP FHS Hash VotingSystem Phoenix.

type cred = voter_id * fhs_pk * fhs_sk.

op cred_id  (e : cred) : voter_id = e.`1.
op cred_upk (e : cred) : fhs_pk   = e.`2.
op cred_usk (e : cred) : fhs_sk   = e.`3.

op lookup (id : voter_id) (store : cred list) : fhs_pk * fhs_sk =
  let matches = filter (fun (e : cred) => cred_id e = id) store in
  let e = head witness matches in
  (cred_upk e, cred_usk e).

module DU_MB_BPRIV_L (BFV : BFV_Scheme) (ZKP : ZKP_Scheme)
                     (FHS : FHS_Scheme) (H   : Hash_Func)
                     (Sim : Tally_Sim) = {

  var bb0     : BB
  var bb1     : BB
  var bb      : BB
  var creds   : cred list
  var checked : voter_id fset
  var happy   : voter_id fset

  proc init (voters : voter_id list) : unit = {
    var id  : voter_id;
    var vs  : voter_id list;
    var upk : fhs_pk;
    var usk : fhs_sk;
    bb0     <- [];
    bb1     <- [];
    bb      <- [];
    creds   <- [];
    checked <- fset0;
    happy   <- fset0;
    Phoenix(BFV,ZKP,FHS,H).setup ();
    vs <- voters;
    while (vs <> []) {
      id  <- head witness vs;
      vs  <- behead vs;
      (upk, usk) <@ Phoenix(BFV,ZKP,FHS,H).register (id);
      creds <- creds ++ [(id, upk, usk)];
    }
  }

  proc vote_lr (id : voter_id, v0 : vote, v1 : vote) : unit = {
    var upk : fhs_pk;
    var usk : fhs_sk;
    var b0  : ballot;
    var b1  : ballot;
    var cr  : fhs_pk * fhs_sk;
    cr      <- lookup id creds;
    upk     <- cr.`1;
    usk     <- cr.`2;
    b0 <@ Phoenix(BFV,ZKP,FHS,H).vote (id, v0, upk, usk);
    b1 <@ Phoenix(BFV,ZKP,FHS,H).vote (id, v1, upk, usk);
    bb0 <- bb0 ++ [b0];
    bb1 <- bb1 ++ [b1];
  }

  proc board () : PBB = {
    var pbb : PBB;
    pbb <@ Phoenix(BFV,ZKP,FHS,H).publish (bb0);
    return pbb;
  }

  proc set_board (adv_bb : BB) : unit = {
    bb <- adv_bb;
  }

  proc tally () : result * tally_proof = {
    var r  : result;
    var pf : tally_proof;
    (r, pf) <@ Phoenix(BFV,ZKP,FHS,H).tally (bb);
    return (r, pf);
  }

  proc verify (id : voter_id) : bool = {
    var pbb : PBB;
    var b   : ballot;
    var bl  : ballot list;
    var ok  : bool;
    checked <- checked `|` fset1 id;
    pbb <@ Phoenix(BFV,ZKP,FHS,H).publish (bb);
    bl  <- filter (fun (b' : ballot) => b_id b' = id) bb0;
    b   <- last witness bl;
    ok  <@ Phoenix(BFV,ZKP,FHS,H).verify_vote (b, pbb);
    if (ok) { happy <- happy `|` fset1 id; }
    return ok;
  }
}.

module DU_MB_BPRIV_R (BFV : BFV_Scheme) (ZKP : ZKP_Scheme)
                     (FHS : FHS_Scheme) (H   : Hash_Func)
                     (Sim : Tally_Sim)  (Rec : Recover_Alg) = {

  var bb0     : BB
  var bb1     : BB
  var bb      : BB
  var creds   : cred list
  var checked : voter_id fset
  var happy   : voter_id fset

  proc init (voters : voter_id list) : unit = {
    var id  : voter_id;
    var vs  : voter_id list;
    var upk : fhs_pk;
    var usk : fhs_sk;
    bb0     <- [];
    bb1     <- [];
    bb      <- [];
    creds   <- [];
    checked <- fset0;
    happy   <- fset0;
    Phoenix(BFV,ZKP,FHS,H).setup ();
    vs <- voters;
    while (vs <> []) {
      id  <- head witness vs;
      vs  <- behead vs;
      (upk, usk) <@ Phoenix(BFV,ZKP,FHS,H).register (id);
      creds <- creds ++ [(id, upk, usk)];
    }
  }

  proc vote_lr (id : voter_id, v0 : vote, v1 : vote) : unit = {
    var upk : fhs_pk;
    var usk : fhs_sk;
    var b0  : ballot;
    var b1  : ballot;
    var cr  : fhs_pk * fhs_sk;
    cr      <- lookup id creds;
    upk     <- cr.`1;
    usk     <- cr.`2;
    b0 <@ Phoenix(BFV,ZKP,FHS,H).vote (id, v0, upk, usk);
    b1 <@ Phoenix(BFV,ZKP,FHS,H).vote (id, v1, upk, usk);
    bb0 <- bb0 ++ [b0];
    bb1 <- bb1 ++ [b1];
  }

  proc board () : PBB = {
    var pbb : PBB;
    pbb <@ Phoenix(BFV,ZKP,FHS,H).publish (bb1);
    return pbb;
  }

  proc set_board (adv_bb : BB) : unit = {
    bb <- adv_bb;
  }

  proc tally () : result * tally_proof = {
    var bb'    : BB;
    var r      : result;
    var pf     : tally_proof;
    var pf_sim : tally_proof;
    var pbb    : PBB;
    bb'     <@ Rec.recover (bb, bb0, bb1);
    (r, pf) <@ Phoenix(BFV,ZKP,FHS,H).tally (bb');
    pbb     <@ Phoenix(BFV,ZKP,FHS,H).publish (bb);
    pf_sim  <@ Sim.simulate (pbb, r);
    return (r, pf_sim);
  }

  proc verify (id : voter_id) : bool = {
    var pbb : PBB;
    var b   : ballot;
    var bl  : ballot list;
    var ok  : bool;
    checked <- checked `|` fset1 id;
    pbb <@ Phoenix(BFV,ZKP,FHS,H).publish (bb1);
    bl  <- filter (fun (b' : ballot) => b_id b' = id) bb1;
    b   <- last witness bl;
    ok  <@ Phoenix(BFV,ZKP,FHS,H).verify_vote (b, pbb);
    if (ok) { happy <- happy `|` fset1 id; }
    return ok;
  }
}.
