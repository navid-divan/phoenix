import tenseal as ts
from ..zkp.system import ZKPSystem
from ..fhs.scheme import FHSScheme
from ..params import BFVParams, ZKPParams, FHSParams


class PhoenixSetup:
    def __init__(self, bfv_params: BFVParams = None, zkp_params: ZKPParams = None, fhs_params: FHSParams = None):
        self.bfv_params = bfv_params or BFVParams()
        self.zkp_params = zkp_params or ZKPParams()
        self.fhs_params = fhs_params or FHSParams()

    def setup(self):
        context = ts.context(
            ts.SCHEME_TYPE.BFV,
            poly_modulus_degree=self.bfv_params.poly_modulus_degree,
            plain_modulus=self.bfv_params.plain_modulus,
        )
        context.generate_galois_keys()
        context.generate_relin_keys()

        secret_key_data = context.secret_key()
        public_context = context.copy()
        public_context.make_context_public()

        pp = ZKPSystem(self.zkp_params).setup()
        fhs = FHSScheme(self.fhs_params)
        fhs_pk, fhs_sk = fhs.setup()

        election_state = {
            "bfv_context": context,
            "bfv_public_context": public_context,
            "bfv_sk": secret_key_data,
            "pp": pp,
            "fhs": fhs,
            "fhs_pk": fhs_pk,
            "fhs_sk": fhs_sk,
        }
        return election_state