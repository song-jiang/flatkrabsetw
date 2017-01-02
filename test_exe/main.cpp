#include <Windows.h>
#include <stdio.h>
#include <flatkrabsetw.h>

void handle_event(const EVENT_RECORD & rec)
{
    printf("event processed - eid: %d, pid: %d",
        rec.EventHeader.EventDescriptor.Id,
        rec.EventHeader.ProcessId);
    printf("\n");
}

int main(void)
{
    krabs_status_ctx status;
    auto trace = krabs_create_user_trace(&status, L"my sweet sweet trace");

    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }

    auto provider = krabs_create_user_provider(
        &status,
        trace,
        L"Microsoft-Windows-PowerShell",
        0xf0010000000003ff,
        0);

    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }

    krabs_add_event_callback_to_provider(&status, provider, handle_event);

    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }

    krabs_enable_user_provider(&status, trace, provider);

    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }

    krabs_start_trace(&status, trace);

    if (status.status != krabs_success)
    {
        printf("error: %s\n", status.msg);
        return 1;
    }
}