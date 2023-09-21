# Authenticated Positioning Using GALILEO Open Service NavigationMessage Authentication (OSNMA)

Research exploring GALILEO OSNMA as means for authenticated positioning

- Paper: [Paper_Authenticated_Positioning(...).pdf](./Paper_Authenticated_Positioning_Using_GALILEO_Open_Service_Navigation_Message_Authentication_(OSNMA).pdf)
  - Provides a brief overview of Galileo OSNMA, provides implementation details and suggest possible flaws in the design of OSNMA:
  - Abstract:

    Problems with the security of GNSS have been made apparent by academics and bad actors alike, with one of the most serious attacks against it being spoofing of navigational data, which trick an unsuspecting user of such a system into receiving incorrect information about their location. In this paper, we explore one of the mechanisms introduced to provide data authentication to GNSS - Galileo OSNMA - such that the data received by the user can be proven to be originating from a satellite rather than from a malicious party. The document presents an example implementation of the protocol and outlines possible flaws in its design that could undermine the security properties proposed for Galileo OSNMA. We make suggestions on how to make it easier for developers to implement and test OSNMA processing in receivers. We also introduce the concept of an official (reference) implementation of an OSNMA processing library.
- Presentation: [Presentation_Authenticated_Positioning_Using_GALILEO_OSNMA.pdf](./Presentation_Authenticated_Positioning_Using_GALILEO_OSNMA.pdf)
  - The slides for the project viva, with visual aids for the possible attacks described in the paper
- [papers](./papers) - Papers relevant to implementing an OSNMA parser
- [py-osnma-parser](./py-osnma-parser/) - OSNMA parser+verifier implemented in python
- [gnss-sdr-osnma](https://github.com/hmk3r/gnss-sdr-osnma) - A GNSS-SDR fork with basic OSNMA processing
