// pub const prev_block_hash: [u8; 32] = [0, 0, 0, 0, 0, 3, 229, 51, 118, 152, 82, 199, 55, 59, 21, 94, 137, 139, 187, 99, 34, 195, 38, 201, 169, 206, 49, 33, 244, 253, 95, 214];
pub const BLOCK_HEADERS: [[u8; 80]; 10] = [[1, 0, 0, 0, 214, 95, 253, 244, 33, 49, 206, 169, 201, 38, 195, 34, 99, 187, 139, 137, 94, 21, 59, 55, 199, 82, 152, 118, 51, 229, 3, 0, 0, 0, 0, 0, 96, 214, 75, 97, 47, 177, 172, 73, 30, 60, 252, 197, 197, 20, 63, 80, 112, 38, 209, 227, 220, 21, 21, 144, 134, 230, 249, 131, 235, 116, 206, 210, 162, 18, 27, 77, 76, 134, 4, 27, 62, 132, 38, 243], [1, 0, 0, 0, 113, 175, 121, 75, 146, 194, 140, 25, 251, 126, 93, 0, 192, 19, 198, 224, 72, 17, 124, 34, 186, 228, 244, 207, 80, 44, 3, 0, 0, 0, 0, 0, 96, 250, 222, 92, 229, 100, 158, 35, 130, 156, 130, 56, 43, 226, 191, 27, 151, 107, 96, 20, 21, 113, 164, 21, 36, 32, 82, 15, 37, 205, 228, 148, 226, 18, 27, 77, 76, 134, 4, 27, 13, 213, 240, 74], [1, 0, 0, 0, 129, 184, 91, 206, 247, 138, 130, 73, 56, 222, 132, 86, 172, 191, 195, 169, 235, 39, 153, 124, 98, 71, 249, 162, 56, 148, 1, 0, 0, 0, 0, 0, 157, 9, 101, 109, 233, 0, 52, 120, 185, 160, 160, 122, 134, 114, 111, 38, 228, 148, 167, 193, 224, 62, 91, 225, 245, 137, 174, 16, 6, 233, 14, 189, 33, 20, 27, 77, 76, 134, 4, 27, 175, 128, 152, 146], [1, 0, 0, 0, 172, 218, 61, 181, 145, 213, 194, 198, 62, 140, 9, 231, 82, 58, 91, 5, 129, 112, 126, 243, 227, 82, 13, 108, 161, 128, 0, 0, 0, 0, 0, 0, 112, 17, 121, 203, 154, 158, 15, 231, 9, 204, 150, 38, 27, 107, 148, 59, 49, 54, 43, 97, 218, 203, 169, 75, 3, 249, 183, 26, 6, 204, 46, 255, 125, 28, 27, 77, 76, 134, 4, 27, 117, 150, 47, 136], [1, 0, 0, 0, 124, 178, 93, 145, 10, 162, 116, 173, 62, 82, 14, 128, 225, 227, 116, 64, 167, 162, 145, 75, 52, 204, 216, 39, 248, 6, 3, 0, 0, 0, 0, 0, 250, 228, 92, 25, 160, 149, 200, 199, 150, 172, 247, 160, 114, 87, 130, 47, 78, 60, 66, 201, 210, 206, 81, 60, 234, 188, 1, 136, 192, 65, 182, 248, 162, 28, 27, 77, 76, 134, 4, 27, 225, 220, 68, 99], [1, 0, 0, 0, 1, 121, 156, 66, 76, 161, 240, 168, 98, 39, 58, 95, 199, 202, 65, 210, 252, 171, 135, 254, 150, 27, 159, 29, 162, 238, 3, 0, 0, 0, 0, 0, 141, 224, 108, 220, 35, 139, 251, 94, 201, 152, 176, 13, 10, 90, 11, 254, 133, 205, 6, 177, 105, 51, 10, 181, 20, 14, 113, 155, 160, 88, 37, 145, 92, 29, 27, 77, 76, 134, 4, 27, 51, 11, 17, 101], [1, 0, 0, 0, 35, 37, 245, 14, 46, 192, 213, 156, 160, 198, 99, 61, 36, 236, 109, 238, 58, 88, 252, 206, 6, 240, 105, 219, 212, 113, 4, 0, 0, 0, 0, 0, 156, 57, 243, 162, 251, 44, 131, 24, 57, 226, 147, 117, 195, 250, 97, 216, 32, 24, 80, 40, 181, 89, 14, 220, 40, 221, 86, 175, 213, 45, 70, 114, 137, 31, 27, 77, 76, 134, 4, 27, 68, 131, 100, 233], [1, 0, 0, 0, 47, 190, 144, 217, 139, 227, 114, 193, 78, 16, 121, 43, 44, 83, 41, 190, 215, 25, 206, 136, 19, 106, 149, 193, 138, 177, 2, 0, 0, 0, 0, 0, 14, 95, 120, 237, 10, 73, 69, 200, 238, 234, 22, 87, 9, 59, 114, 16, 164, 85, 76, 137, 137, 193, 27, 232, 248, 43, 103, 47, 151, 229, 64, 81, 110, 32, 27, 77, 76, 134, 4, 27, 18, 73, 104, 27], [1, 0, 0, 0, 232, 248, 169, 211, 74, 211, 0, 222, 33, 119, 168, 238, 29, 100, 2, 238, 166, 118, 62, 80, 149, 79, 208, 170, 87, 246, 1, 0, 0, 0, 0, 0, 10, 171, 178, 116, 150, 201, 203, 252, 162, 190, 103, 239, 168, 126, 236, 111, 162, 25, 118, 121, 74, 242, 184, 25, 73, 183, 37, 3, 59, 173, 160, 243, 129, 32, 27, 77, 76, 134, 4, 27, 138, 228, 143, 188], [1, 0, 0, 0, 209, 83, 236, 200, 39, 165, 49, 101, 44, 67, 13, 136, 149, 176, 127, 104, 150, 9, 25, 103, 210, 16, 121, 99, 3, 33, 0, 0, 0, 0, 0, 0, 144, 122, 84, 161, 215, 20, 172, 87, 216, 196, 60, 140, 197, 181, 112, 6, 3, 47, 195, 165, 222, 109, 151, 148, 58, 30, 138, 85, 47, 217, 14, 17, 179, 33, 27, 77, 76, 134, 4, 27, 178, 136, 3, 232]];
/// Merkle root of the RECURSION_CONTROL_IDS
pub const ALLOWED_IDS_ROOT: &str =
    "6df708447638d36828ebf4545980ff39315562181c926d3a9e2697405f3acf15";