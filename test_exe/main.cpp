#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <flatkrabsetw.h>

#pragma comment(lib, "Ws2_32.lib")

void handle_event(const EVENT_RECORD *rec)
{
    auto eid = rec->EventHeader.EventDescriptor.Id;

    krabs_status_ctx status;

    //printf("Recieved event id %d\n", eid);

    auto schema = krabs_get_event_schema(&status, rec);
    if (status.status != krabs_success) {
        printf("error: %s\n", status.msg);
        return;
    }

    auto parser = krabs_get_event_parser(&status, schema);
    if (status.status != krabs_success) {
        printf("error: %s\n", status.msg);
        return;
    }

    // Get the size.
    uint32_t pid = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"PID");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        pid = krabs_get_u32_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    // Get the size.
    uint32_t size = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"size");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        size = krabs_get_u32_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    // Get the Dport.
    uint16_t dport = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"dport");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        dport = krabs_get_u16_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
        dport = (dport << 8) | (dport >> 8);
    }

    // Get the Dport.
    uint16_t sport = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"sport");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        sport = krabs_get_u16_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
        sport = (sport << 8) | (sport >> 8);
    }

    // Get the Daddr.
    krabs_ip_address *daddr = nullptr;
    {
        auto prop_name = krabs_create_property_name(&status, L"daddr");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        daddr = krabs_get_ip_addr_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    // Get the Saddr.
    krabs_ip_address *saddr = nullptr;
    {
        auto prop_name = krabs_create_property_name(&status, L"saddr");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        saddr = krabs_get_ip_addr_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    char saddr_str[48] = { 0 };
    if (saddr->is_ipv6) {
        inet_ntop(AF_INET6, &saddr->v6, &saddr_str[0], ARRAYSIZE(saddr_str));
    }
    else {
        inet_ntop(AF_INET, &saddr->v4, &saddr_str[0], ARRAYSIZE(saddr_str));
    }

    char daddr_str[48] = { 0 };
    if (daddr->is_ipv6) {
        inet_ntop(AF_INET6, &daddr->v6, &daddr_str[0], ARRAYSIZE(saddr_str));
    }
    else {
        inet_ntop(AF_INET, &daddr->v4, &daddr_str[0], ARRAYSIZE(saddr_str));
    }

    // Return if it is not Pod CIDR
    if (strncmp(saddr_str, "192.168", 7) != 0 && strncmp(daddr_str, "192.168", 7) != 0) {
        delete saddr;
        delete daddr;
        return;
    }

    switch (eid) {
    case 10:
        printf("provider(KNL) event(%d) TCPv4: ", eid);
        break;
    case 26:
        printf("provider(KNL) event(%d) TCPv6: ", eid);
        break;
    case 42:
        printf("provider(KNL) event(%d) UDPv4: ", eid);
        break;
    case 58:
        printf("provider(KNL) event(%d) UDPv6: ", eid);
        break;
    case 13:
        printf("provider(KNL) event(%d) TCPv4: connection closed ", eid);
        break;
    case 15:
        printf("provider(KNL) event(%d) TCPv4: connection established ", eid);
        break;
    default:
        printf("Recieved event id %d unknown\n", eid);
        return;
    }

    if (eid == 13 || eid == 15) {
        printf("between %s:%d and %s:%d  ",
            saddr_str,
            sport,
            daddr_str,
            dport);

    } else {
        printf("%d bytes %s:%d ----> %s:%d  ",
            size,
            saddr_str,
            sport,
            daddr_str,
            dport);
    }

    if (daddr) {
        delete daddr;
    }
    if (saddr) {
        delete saddr;
    }
    krabs_destroy_event_parser(parser);
    krabs_destroy_event_schema(schema);

    printf("\n");
}

void handle_event_vfp(const EVENT_RECORD *rec)
{
    auto eid = rec->EventHeader.EventDescriptor.Id;

    krabs_status_ctx status;

    //printf("Recieved event id %d\n", eid);

    auto schema = krabs_get_event_schema(&status, rec);
    if (status.status != krabs_success) {
        printf("error: %s\n", status.msg);
        return;
    }

    auto parser = krabs_get_event_parser(&status, schema);
    if (status.status != krabs_success) {
        printf("error: %s\n", status.msg);
        return;
    }

    // Get rule type.
    uint8_t rule_type = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"RuleType");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        rule_type = krabs_get_u8_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    // Return if it is not Allow or Deny rule
    if (rule_type != 1 && rule_type != 2) {
        return;
    }

    // Get the port id
    uint32_t port_id = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"PortId");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        port_id = krabs_get_u32_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    // Get the direction.
    uint8_t dir = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"Direction");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        dir = krabs_get_u8_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    // Get ip protocol.
    uint8_t protocol = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"IpProtocol");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        protocol = krabs_get_u8_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    // Get the Dport.
    uint16_t dport = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"DstPort");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        dport = krabs_get_u16_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
        dport = (dport << 8) | (dport >> 8);
    }

    // Get the Dport.
    uint16_t sport = 0;
    {
        auto prop_name = krabs_create_property_name(&status, L"SrcPort");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        sport = krabs_get_u16_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
        sport = (sport << 8) | (sport >> 8);
    }

    // Get the Daddr.
    krabs_ip_address *daddr = nullptr;
    {
        auto prop_name = krabs_create_property_name(&status, L"DstIpv4Addr");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        daddr = krabs_get_ip_addr_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    // Get the Saddr.
    krabs_ip_address *saddr = nullptr;
    {
        auto prop_name = krabs_create_property_name(&status, L"SrcIpv4Addr");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        saddr = krabs_get_ip_addr_property_from_parser(
            &status,
            parser,
            prop_name);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    char saddr_str[48] = { 0 };
    if (saddr->is_ipv6) {
        inet_ntop(AF_INET6, &saddr->v6, &saddr_str[0], ARRAYSIZE(saddr_str));
    }
    else {
        inet_ntop(AF_INET, &saddr->v4, &saddr_str[0], ARRAYSIZE(saddr_str));
    }

    char daddr_str[48] = { 0 };
    if (daddr->is_ipv6) {
        inet_ntop(AF_INET6, &daddr->v6, &daddr_str[0], ARRAYSIZE(saddr_str));
    }
    else {
        inet_ntop(AF_INET, &daddr->v4, &daddr_str[0], ARRAYSIZE(saddr_str));
    }
    if (strncmp(saddr_str, "192.168", 7) != 0 && strncmp(daddr_str, "192.168", 7) != 0) {
        delete saddr;
        delete daddr;
        return;
    }

    // Get the rule id.
    wchar_t* rule_id = nullptr;
    {
        auto prop_name = krabs_create_property_name(&status, L"RuleId");
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        rule_id = krabs_get_string_property_from_parser(
            &status,
            parser,
            prop_name,
            krabs_string_type::std_wstring);
        if (status.status != krabs_success) {
            printf("error: %s\n", status.msg);
            return;
        }

        krabs_destroy_property_name(prop_name);
    }

    wchar_t type_string[3][10] = {
                        L"N/A",
                        L"allow",
                        L"deny"
    };
    char dir_string[2][10] = {
                             "outbound",
                             "inbound"
    };

    switch (eid) {
    case 101:
        wprintf(L"provider(VFP) event(%d) Hit rule (%s) PortId: %d RuleId: %s ", eid, type_string[rule_type], port_id, rule_id);
        break;
    default:
        printf("Recieved event id %d unknown\n", eid);
        return;
    }

    printf("%s protocol (%d) %s:%d ----> %s:%d  ",
        dir_string[dir],
        protocol,
        saddr_str,
        sport,
        daddr_str,
        dport);

    if (daddr) {
        delete daddr;
    }
    if (saddr) {
        delete saddr;
    }
    krabs_destroy_event_parser(parser);
    krabs_destroy_event_schema(schema);

    printf("\n");
}

int main(void)
{
    krabs_status_ctx status;
    auto trace = krabs_create_user_trace(&status, L"song flow log trace");
    printf("User Trace created.\n");

    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }

    auto provider = krabs_create_user_provider(
        &status,
        L"Microsoft-Windows-Kernel-Network",
        0x8000000000000000,
        0);

    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Created user provider Microsoft-Windows-Kernel-Network\n");

    auto provider_vfp = krabs_create_user_provider(
        &status,
        L"Microsoft-Windows-Hyper-V-VfpExt",
        0x8000000000000000,
        0);

    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Created user provider Microsoft-Windows-Hyper-V-VfpExt\n");

    USHORT event_ids[] = {
        10,
        13,
        15,
        26,
        42,
        58
    };

    USHORT event_ids_vfp[] = {
        101
    };


    auto filter = krabs_create_filter_for_event_ids(&status, &event_ids[0], ARRAYSIZE(event_ids));
    if (status.status != krabs_success) {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Created filter for tcpip connection events.\n");

    auto filter_vfp = krabs_create_filter_for_event_ids(&status, &event_ids_vfp[0], ARRAYSIZE(event_ids));
    if (status.status != krabs_success) {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Created filter for vfp allow/deny rules events.\n");

    krabs_add_callback_to_event_filter(&status, filter, handle_event);
    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Added callback function handling events from provider Microsoft-Windows-Kernel-Network.\n");

    krabs_add_callback_to_event_filter(&status, filter_vfp, handle_event_vfp);
    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Added callback function handling events from provider Microsoft-Windows-Hyper-V-VfpEx.\n");

    krabs_add_event_filter_to_user_provider(&status, provider, filter);
    if (status.status != krabs_success) {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Added event filter to provider Microsoft-Windows-Kernel-Network.\n");

    krabs_add_event_filter_to_user_provider(&status, provider_vfp, filter_vfp);
    if (status.status != krabs_success) {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Added event filter to provider Microsoft-Windows-Hyper-V-VfpEx.\n");

    krabs_enable_user_provider(&status, trace, provider);
    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Enable provider Microsoft-Windows-kernel-network.\n");

    krabs_enable_user_provider(&status, trace, provider_vfp);
    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("Enable provider Microsoft-Windows-Hyper-V-VfpEx.\n");

    printf("Start thread to capture trace...\n\n\n");

    krabs_start_user_trace(&status, trace);

    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }
    printf("we are done\n");
}