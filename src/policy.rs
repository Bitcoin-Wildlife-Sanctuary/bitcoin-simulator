pub struct Policy {
    pub sat_per_vbyte: u32,
    pub allow_data_carrier_via_op_return: bool,
    pub require_dust_amount: bool,
    pub max_tx_weight: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            sat_per_vbyte: 1,
            allow_data_carrier_via_op_return: false, /* subject to many spam filters */
            require_dust_amount: true,
            max_tx_weight: 400000,
        }
    }
}

impl Policy {
    pub fn no_spam_filter(mut self) -> Self {
        self.allow_data_carrier_via_op_return = true;
        self
    }

    pub fn no_dust_amount_requirement(mut self) -> Self {
        self.require_dust_amount = false;
        self
    }

    pub fn set_fee(mut self, sat_per_vbyte: u32) -> Self {
        self.sat_per_vbyte = sat_per_vbyte;
        self
    }

    pub fn set_max_tx_weight(mut self, max_tx_weight: u32) -> Self {
        self.max_tx_weight = max_tx_weight;
        self
    }
}
