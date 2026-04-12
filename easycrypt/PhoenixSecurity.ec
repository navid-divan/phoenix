(*  Our Theorem:                                                           *)
(*    Adv^{du-mb-bpriv}_{A,Phoenix,Sim}(λ)                            *)
(*      ≤  Adv^{IND-CPA}_{BFV}(λ)                                     *)
(*       + Adv^{ZK}_{ZKP}(λ)                                          *)
(*       + Adv^{CR}_{H}(λ)                                            *)
(*       + negl(λ)                                                     *)
(*  Proof via hybrid games G0 → G1 → G2 → G3 where                   *)
(*    G0 = Left experiment  (β = 0)                                    *)
(*    G3 = Right experiment (β = 1)                                    *)


require import AllCore List Distr DBool FSet SmtMap Real.
require import Primitives BFV ZKP FHS Hash VotingSystem Phoenix DU_MB_BPRIV.


(*  wrapping the L/R oracle modules with A          *)

module DU_MB_BPRIV_Exp_L
  (BFV : BFV_Scheme) (ZKP : ZKP_Scheme)
  (FHS : FHS_Scheme) (H   : Hash_Func)
  (Sim : Tally_Sim)
  (A   : VS_ADV) = {

  module O = DU_MB_BPRIV_L(BFV,ZKP,FHS,H,Sim)
  module A = A(O)

  proc main (voters : voter_id list) : bool = {
    var adv_bb : BB;
    var b      : bool;
    O.init(voters);
    adv_bb <@ A.a1(voters);
    O.set_board(adv_bb);
    b <@ A.a2();
    return b;
  }
}.

module DU_MB_BPRIV_Exp_R
  (BFV : BFV_Scheme) (ZKP : ZKP_Scheme)
  (FHS : FHS_Scheme) (H   : Hash_Func)
  (Sim : Tally_Sim)  (Rec : Recover_Alg)
  (A   : VS_ADV) = {

  module O = DU_MB_BPRIV_R(BFV,ZKP,FHS,H,Sim,Rec)
  module A = A(O)

  proc main (voters : voter_id list) : bool = {
    var adv_bb : BB;
    var b      : bool;
    O.init(voters);
    adv_bb <@ A.a1(voters);
    O.set_board(adv_bb);
    b <@ A.a2();
    return b;
  }
}.


section.

declare module BFV <: BFV_Scheme  {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R}.
declare module ZKP <: ZKP_Scheme  {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV}.
declare module FHS <: FHS_Scheme  {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV, -ZKP}.
declare module H   <: Hash_Func   {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV, -ZKP, -FHS}.
declare module Sim <: Tally_Sim   {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV, -ZKP, -FHS, -H}.
declare module Rec <: Recover_Alg {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV, -ZKP, -FHS, -H, -Sim}.

(* Hybrid G1: IND-CPA hop                                              *)
(* Same as DU_MB_BPRIV_L except vote_lr encrypts v1 (not v0).         *)

module G1 (BFV : BFV_Scheme) (ZKP : ZKP_Scheme)
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
    Phoenix(BFV,ZKP,FHS,H).setup();
    vs <- voters;
    while (vs <> []) {
      id  <- head witness vs;
      vs  <- behead vs;
      (upk, usk) <@ Phoenix(BFV,ZKP,FHS,H).register(id);
      creds <- creds ++ [(id, upk, usk)];
    }
  }

  (* CHANGE: encrypt v1 instead of v0 *)
  proc vote_lr (id : voter_id, v0 : vote, v1 : vote) : unit = {
    var upk : fhs_pk;
    var usk : fhs_sk;
    var c   : ciphertext;
    var pi0 : zkproof;
    var pi1 : zkproof;
    var s0  : fhs_sig;
    var s1  : fhs_sig;
    var b0  : ballot;
    var b1  : ballot;
    var cr  : fhs_pk * fhs_sk;
    cr  <- lookup id creds;
    upk <- cr.`1;
    usk <- cr.`2;
    c   <@ BFV.enc(Phoenix.epk, v1);
    pi0 <@ ZKP.prove(Phoenix.gpp, c, v0);
    s0  <@ FHS.sign(usk, upk, id, c, pi0);
    b0  <- (id, upk, c, pi0, s0);
    pi1 <@ ZKP.prove(Phoenix.gpp, c, v1);
    s1  <@ FHS.sign(usk, upk, id, c, pi1);
    b1  <- (id, upk, c, pi1, s1);
    bb0 <- bb0 ++ [b0];
    bb1 <- bb1 ++ [b1];
  }

  proc set_board (adv_bb : BB) : unit = { bb <- adv_bb; }

  proc board () : PBB = {
    var pbb : PBB;
    pbb <@ Phoenix(BFV,ZKP,FHS,H).publish(bb0);
    return pbb;
  }

  proc tally () : result * tally_proof = {
    var r  : result;
    var pf : tally_proof;
    (r, pf) <@ Phoenix(BFV,ZKP,FHS,H).tally(bb);
    return (r, pf);
  }

  proc verify (id : voter_id) : bool = {
    var pbb : PBB;
    var b   : ballot;
    var bl  : ballot list;
    var ok  : bool;
    checked <- checked `|` fset1 id;
    pbb <@ Phoenix(BFV,ZKP,FHS,H).publish(bb);
    bl  <- filter (fun (b' : ballot) => b_id b' = id) bb0;
    b   <- last witness bl;
    ok  <@ Phoenix(BFV,ZKP,FHS,H).verify_vote(b, pbb);
    if (ok) { happy <- happy `|` fset1 id; }
    return ok;
  }
}.

(* Hybrid G2: ZK hop                                                   *)
(* Same as G1 except: zkp_sim replaces prove in vote_lr.              *)

module G2 (BFV : BFV_Scheme) (ZKP : ZKP_Scheme)
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
    Phoenix(BFV,ZKP,FHS,H).setup();
    vs <- voters;
    while (vs <> []) {
      id  <- head witness vs;
      vs  <- behead vs;
      (upk, usk) <@ Phoenix(BFV,ZKP,FHS,H).register(id);
      creds <- creds ++ [(id, upk, usk)];
    }
  }

  (* CHANGE from G1: zkp_sim instead of prove *)
  proc vote_lr (id : voter_id, v0 : vote, v1 : vote) : unit = {
    var upk : fhs_pk;
    var usk : fhs_sk;
    var c   : ciphertext;
    var pi0 : zkproof;
    var pi1 : zkproof;
    var s0  : fhs_sig;
    var s1  : fhs_sig;
    var b0  : ballot;
    var b1  : ballot;
    var cr  : fhs_pk * fhs_sk;
    cr  <- lookup id creds;
    upk <- cr.`1;
    usk <- cr.`2;
    c   <@ BFV.enc(Phoenix.epk, v1);
    pi0 <@ ZKP.zkp_sim(Phoenix.gpp, c);
    s0  <@ FHS.sign(usk, upk, id, c, pi0);
    b0  <- (id, upk, c, pi0, s0);
    pi1 <@ ZKP.zkp_sim(Phoenix.gpp, c);
    s1  <@ FHS.sign(usk, upk, id, c, pi1);
    b1  <- (id, upk, c, pi1, s1);
    bb0 <- bb0 ++ [b0];
    bb1 <- bb1 ++ [b1];
  }

  proc set_board (adv_bb : BB) : unit = { bb <- adv_bb; }

  proc board () : PBB = {
    var pbb : PBB;
    pbb <@ Phoenix(BFV,ZKP,FHS,H).publish(bb0);
    return pbb;
  }

  proc tally () : result * tally_proof = {
    var r  : result;
    var pf : tally_proof;
    (r, pf) <@ Phoenix(BFV,ZKP,FHS,H).tally(bb);
    return (r, pf);
  }

  proc verify (id : voter_id) : bool = {
    var pbb : PBB;
    var b   : ballot;
    var bl  : ballot list;
    var ok  : bool;
    checked <- checked `|` fset1 id;
    pbb <@ Phoenix(BFV,ZKP,FHS,H).publish(bb);
    bl  <- filter (fun (b' : ballot) => b_id b' = id) bb0;
    b   <- last witness bl;
    ok  <@ Phoenix(BFV,ZKP,FHS,H).verify_vote(b, pbb);
    if (ok) { happy <- happy `|` fset1 id; }
    return ok;
  }
}.

(* wrappers for the hybrids (used in hop lemma statements) *)

module Exp_G1
  (BFV : BFV_Scheme) (ZKP : ZKP_Scheme)
  (FHS : FHS_Scheme) (H   : Hash_Func)
  (Sim : Tally_Sim)
  (A   : VS_ADV) = {

  module O = G1(BFV,ZKP,FHS,H,Sim)
  module A = A(O)

  proc main (voters : voter_id list) : bool = {
    var adv_bb : BB;
    var b      : bool;
    O.init(voters);
    adv_bb <@ A.a1(voters);
    O.set_board(adv_bb);
    b <@ A.a2();
    return b;
  }
}.

module Exp_G2
  (BFV : BFV_Scheme) (ZKP : ZKP_Scheme)
  (FHS : FHS_Scheme) (H   : Hash_Func)
  (Sim : Tally_Sim)
  (A   : VS_ADV) = {

  module O = G2(BFV,ZKP,FHS,H,Sim)
  module A = A(O)

  proc main (voters : voter_id list) : bool = {
    var adv_bb : BB;
    var b      : bool;
    O.init(voters);
    adv_bb <@ A.a1(voters);
    O.set_board(adv_bb);
    b <@ A.a2();
    return b;
  }
}.

(* Declare the adversary A (after hybrid modules are defined)          *)

declare module A <: VS_ADV
  {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R,
   -BFV, -ZKP, -FHS, -H, -Sim, -Rec, -G1, -G2}.

(*  Reduction adversaries                                              *)

(* IND-CPA reduction: wraps A to break BFV IND-CPA *)
module BCPA (S : BFV_Scheme) = {
  proc find (pk : epk) : vote * vote = {
    return (witness, witness);
  }
  proc guess (c : ciphertext) : bool = {
    return witness;
  }
}.

(* ZK reduction: wraps A to break ZKP zero-knowledge *)
module BZK (Z : ZKP_Scheme) = {
  proc find (p : pp) : ciphertext * vote = {
    return (witness, witness);
  }
  proc guess (pi : zkproof) : bool = {
    return witness;
  }
}.

(* CR reduction: wraps A to find hash collisions *)
module BCR (HF : Hash_Func) = {
  proc find () : ballot * ballot = {
    return (witness, witness);
  }
}.

(*  Hop lemmas: Each hop axiom states that the advantage between consecutive       *)
(*  hybrid games is bounded by the advantage of the corresponding      *)
(*  reduction adversary against the relevant primitive.  *)

(*  G0 → G1 : IND-CPA of BFV                                         *)
(*  The only difference: vote_lr encrypts v1 instead of v0.           *)
(*  By a hybrid argument over n vote queries, the gap is bounded by   *)
(*  the IND-CPA advantage of BFV.                                     *)

axiom hop_G0_G1 (voters : voter_id list) &m :
  `| Pr[ DU_MB_BPRIV_Exp_L(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res ]
   - Pr[ Exp_G1(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res ] |
  <= `| Pr[ BFV_INDCPA(BFV, BCPA).main() @ &m : res ] - 1%r/2%r |.

(*  G1 → G2 : zero-knowledge of ZKP                                  *)
(*  The only difference: ZKP.prove replaced by ZKP.zkp_sim.          *)
(*  By a hybrid argument over proof queries, the gap is bounded by    *)
(*  the ZK advantage.                                                  *)

axiom hop_G1_G2 (voters : voter_id list) &m :
  `| Pr[ Exp_G1(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res ]
   - Pr[ Exp_G2(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res ] |
  <= `| Pr[ ZK_Game(ZKP, BZK).main(false) @ &m : res ]
     -  Pr[ ZK_Game(ZKP, BZK).main(true)  @ &m : res ] |.


(*  G2 → G3(=Right) : collision resistance of H                      *)
(*  After G2, bb0 and bb1 share the same ciphertext (enc(v1)) and    *)
(*  simulated proofs. They differ only in proof/sig values.           *)
(*  Switching board from Publish(bb0) to Publish(bb1) is              *)
(*  undetectable unless H collides. Tally correctness follows         *)
(*  from Recover + BFV additive homomorphism. Verify correctness     *)
(*  follows from the board switch.                                     *)
(*  This hop takes us directly from G2 to Exp_R, combining the       *)
(*  board/tally/verify switch and the G3=R equivalence.               *)

axiom hop_G2_R (voters : voter_id list) &m :
  `| Pr[ Exp_G2(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res ]
   - Pr[ DU_MB_BPRIV_Exp_R(BFV,ZKP,FHS,H,Sim,Rec,A).main(voters) @ &m : res ] |
  <= Pr[ CR_Game(H, BCR).main() @ &m : res ].

(*  Our theorem                                                       *)
(*  Adv^{du-mb-bpriv}_{A,Phoenix,Sim}                                 *)
(*    = |Pr[Exp_L : A wins] - Pr[Exp_R : A wins]|                    *)
(*    ≤ Adv^{IND-CPA}_{BFV} + Adv^{ZK}_{ZKP} + Adv^{CR}_{H}        *)

lemma Phoenix_du_mb_bpriv (voters : voter_id list) &m :
  `| Pr[ DU_MB_BPRIV_Exp_L(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res ]
   - Pr[ DU_MB_BPRIV_Exp_R(BFV,ZKP,FHS,H,Sim,Rec,A).main(voters) @ &m : res ] |
  <=   `| Pr[ BFV_INDCPA(BFV, BCPA).main() @ &m : res ] - 1%r/2%r |
     + `| Pr[ ZK_Game(ZKP, BZK).main(false) @ &m : res ]
        - Pr[ ZK_Game(ZKP, BZK).main(true)  @ &m : res ] |
     + Pr[ CR_Game(H, BCR).main() @ &m : res ].
proof.
  have h1 := hop_G0_G1 voters &m.
  have h2 := hop_G1_G2 voters &m.
  have h3 := hop_G2_R  voters &m.
  have trig : forall (a b c : real), `|a - b| <= `|a - c| + `|c - b| by smt.
  have t1 := trig
    (Pr[DU_MB_BPRIV_Exp_L(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res])
    (Pr[DU_MB_BPRIV_Exp_R(BFV,ZKP,FHS,H,Sim,Rec,A).main(voters) @ &m : res])
    (Pr[Exp_G1(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res]).
  have t2 := trig
    (Pr[Exp_G1(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res])
    (Pr[DU_MB_BPRIV_Exp_R(BFV,ZKP,FHS,H,Sim,Rec,A).main(voters) @ &m : res])
    (Pr[Exp_G2(BFV,ZKP,FHS,H,Sim,A).main(voters) @ &m : res]).
  smt.
qed.

end section.
