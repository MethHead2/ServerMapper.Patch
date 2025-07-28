#include "GetHWID.h"

// SHA256 class definition
class SHA256 {
public:
    static const uint32_t sha256_k[];
    static const unsigned int DIGEST_SIZE = (256 / 8);
    void init();
    void update(const uint8_t* message, unsigned int len);
    void final(uint8_t* digest);

private:
    void transform(const uint8_t* message, unsigned int block_nb);
    unsigned int m_tot_len;
    unsigned int m_len;
    uint8_t m_block[2 * 64];
    uint32_t m_h[8];

    static inline uint32_t ROTR(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
    static inline uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    static inline uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static inline uint32_t SHA256_F1(uint32_t x) {
        return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    }
    static inline uint32_t SHA256_F2(uint32_t x) {
        return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    }
    static inline uint32_t SHA256_F3(uint32_t x) {
        return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
    }
    static inline uint32_t SHA256_F4(uint32_t x) {
        return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
    }
};

const uint32_t SHA256::sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void SHA256::init() {
    VMProtectBeginUltra("init");
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
    VMProtectEnd();
}

void SHA256::transform(const uint8_t* message, unsigned int block_nb) {
    VMProtectBeginUltra("transform");
    uint32_t w[64];
    uint32_t wv[8];
    uint32_t t1, t2;
    const uint8_t* sub_block;

    for (int i = 0; i < (int)block_nb; i++) {
        sub_block = message + (i << 6);
        for (int j = 0; j < 16; j++) {
            memcpy(&w[j], &sub_block[j << 2], 4);
        }
        for (int j = 16; j < 64; j++) {
            w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (int j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (int j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6]) + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (int j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
    VMProtectEnd();
}

void SHA256::update(const uint8_t* message, unsigned int len) {
    VMProtectBeginUltra("update");
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const uint8_t* shifted_message;

    tmp_len = 64 - m_len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&m_block[m_len], message, rem_len);

    if (m_len + len < 64) {
        m_len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / 64;

    shifted_message = message + rem_len;

    transform(m_block, 1);
    transform(shifted_message, block_nb);

    rem_len = new_len % 64;

    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);

    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
    VMProtectEnd();
}

void SHA256::final(uint8_t* digest) {
    VMProtectBeginUltra("final");
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

    block_nb = (1 + ((64 - 9) < (m_len % 64)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;

    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    memcpy(m_block + pm_len - 4, &len_b, 4);

    transform(m_block, block_nb);

    for (int i = 0; i < 8; i++) {
        memcpy(&digest[i << 2], &m_h[i], 4);
    }
    VMProtectEnd();
}

// Function to hash the HWID with SHA-256
std::string HashHWID(const std::string& hwid) {
    SHA256 sha256;
    uint8_t digest[SHA256::DIGEST_SIZE];
    sha256.init();
    sha256.update(reinterpret_cast<const uint8_t*>(hwid.data()), hwid.size());
    sha256.final(digest);

    std::ostringstream oss;
    for (size_t i = 0; i < sizeof(digest); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return oss.str();
}

// Function to execute a command and get the output
std::string exec(const char* cmd) {
    VMProtectBeginUltra("exec");
    std::array<char, 128> buffer;
    std::string result;
    FILE* pipe = _popen(cmd, (VMProtectDecryptStringA("r"))); // Use _popen instead of popen
    if (!pipe) throw std::runtime_error((VMProtectDecryptStringA("popen() failed!")));
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    _pclose(pipe); // Use _pclose instead of pclose
    return result;
    VMProtectEnd();
}

// Function to get a list of hardware IDs (like CPU serial, etc.) using cmd
std::vector<std::string> GetHWIDs() {
    VMProtectBeginUltra("GetHWIDs");
    std::vector<std::string> hwids;
    hwids.push_back(exec((VMProtectDecryptStringA("wmic cpu get ProcessorId"))));
    hwids.push_back(exec((VMProtectDecryptStringA("wmic bios get serialnumber"))));
   // hwids.push_back(exec("wmic diskdrive get serialnumber"));
    hwids.push_back(exec((VMProtectDecryptStringA("wmic baseboard get serialnumber"))));
    hwids.push_back(exec((VMProtectDecryptStringA("wmic path win32_computersystemproduct get uuid"))));
    return hwids;
    VMProtectEnd();
}

