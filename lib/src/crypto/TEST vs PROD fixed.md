1. Corrected Session Key Derivation (Counters)
The primary failure was due to using the wrong Key Derivation Function (KDF) counters for the Secure Messaging (SM) session keys.

Before: The library used counters 3 (for Encryption) and 4 (for MAC), which are reserved for the initial PACE Key Mapping (K_pi).
After: We switched to using counters 1 (Encryption) and 2 (for MAC). This is mandated by the ICAO 9303 standard for the actual data transmission session that occurs after the initial handshake.
2. Standardized MAC Calculation (CMAC)
The calculation of the Message Authentication Code (MAC) for APDU commands was misaligned with the JMRTD reference implementation.

Header Padding: We now enforce padding the APDU header to the block size before calculating the MAC.
SSC Inclusion: The Send Sequence Counter (SSC) is now correctly prepended to the data stream before the MAC is calculated.
DO97 Handling: We added logic to strictly omit the DO97 data object (expected length) when Le is 0. The previous version sometimes included it incorrectly, causing the card to reject the signature.
3. Send Sequence Counter (SSC) Initialization
Fix: The Send Sequence Counter used to track the order of messages is now explicitly initialized to 0 at the start of the secure session. The previous version attempted to derive an initial value from ephemeral keys, which is valid for some protocols but incorrect for the standard PACE-to-AES session used by these eIDs.
