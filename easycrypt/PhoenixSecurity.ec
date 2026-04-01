require import AllCore List Distr DBool FSet SmtMap Real.
require import Primitives BFV ZKP FHS Hash VotingSystem Phoenix DU_MB_BPRIV.

section.

declare module BFV <: BFV_Scheme  {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R}.
declare module ZKP <: ZKP_Scheme  {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV}.
declare module FHS <: FHS_Scheme  {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV, -ZKP}.
declare module H   <: Hash_Func   {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV, -ZKP, -FHS}.
declare module Sim <: Tally_Sim   {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV, -ZKP, -FHS, -H}.
declare module Rec <: Recover_Alg {-Phoenix, -DU_MB_BPRIV_L, -DU_MB_BPRIV_R, -BFV, -ZKP, -FHS, -H, -Sim}.

lemma Phoenix_du_mb_bpriv
  (voters : voter_id list) &m :
  `| Pr[ DU_MB_BPRIV_L(BFV,ZKP,FHS,H,Sim).init(voters) @ &m : true ]
   - Pr[ DU_MB_BPRIV_R(BFV,ZKP,FHS,H,Sim,Rec).init(voters) @ &m : true ] |
  = 0%r.
proof. admit. qed.

end section.
