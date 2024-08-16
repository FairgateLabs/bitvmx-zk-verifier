// #######################
// ### RISC0 CONSTANTS ###
// #######################

// vk
const unsigned char BYTES_ALPHA[32] = {vk_alpha_g1};
const unsigned char BYTES_BETA[64] = {vk_beta_g2};
const unsigned char BYTES_GAMMA[64] = {vk_gamma_g2};
const unsigned char BYTES_DELTA[64] = {vk_delta_g2};
const unsigned char BYTES_GAMMA_ABC[6][32] = {{vk_gamma_abc_0}, {vk_gamma_abc_1}, {vk_gamma_abc_2}, {vk_gamma_abc_3}, {vk_gamma_abc_4}, {vk_gamma_abc_5}};

// first two public inputs are constant
unsigned char BYTES_PUBLIC_INPUTS[5][32] = {{public_input_0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {public_input_1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},{public_input_4a, public_input_4b }};

// receipt claim tag, output tag, claim input
const unsigned char RECEIPT_CLAIM_TAG[] = {receipt_claim_tag};
const unsigned char OUTPUT_TAG[] = {output_tag};
const unsigned char CLAIM_INPUT[] = {claim_input};

// helper
const unsigned char ZEROS[] = {zeroes};
const unsigned char TWO_U16[] = {two_u16};
const unsigned char FOUR_U16[] = {four_u16};
const unsigned char ZERO_U32[] = {zero_u32};

// #########################
// ### CIRCUIT CONSTANTS ###
// #########################

const unsigned char CLAIM_PRE[] = {claim_pre};

// #######################
// ### PROOF CONSTANTS ###
// #######################

// claim post
const unsigned char CLAIM_POST[] = {claim_post};

// proof
unsigned char BYTES_PROOF_A[32] = {proof_a};
unsigned char BYTES_PROOF_B[64] = {proof_b};
unsigned char BYTES_PROOF_C[32] = {proof_c};

// journal
unsigned char JOURNAL[] = {journalx};
