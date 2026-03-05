import { SlackIntegration } from '../src/application/SlackIntegration';

describe('SlackIntegration', () => {
    it('should format and log the approval request properly', async () => {
        const slack = new SlackIntegration();
        const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
        
        const mockAlert = {
            alert_id: 'abc-123',
            event_id: 'event-999',
            xai_explanation: 'High risk PII found.',
            proposed_redaction_policy: 'REDACT_ENTITIES:SSN'
        };
        
        await slack.sendApprovalRequest(mockAlert);
        
        expect(consoleSpy).toHaveBeenCalled();
        const loggedCall = consoleSpy.mock.calls[0][1];
        expect(loggedCall).toContain('abc-123');
        expect(loggedCall).toContain('REDACT_ENTITIES:SSN');
        expect(loggedCall).toContain('Approve Remediation');
        
        consoleSpy.mockRestore();
    });
});