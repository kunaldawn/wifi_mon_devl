struct prism2_pkthdr {
    u_int32_t host_time;
    u_int32_t mac_time;
    u_int32_t channel;
    u_int32_t rssi;
    u_int32_t sq;
    int       signal;
    int       noise;
    u_int32_t rate;
    u_int32_t istx;
    u_int32_t frmlen;
} _PACKED_;
