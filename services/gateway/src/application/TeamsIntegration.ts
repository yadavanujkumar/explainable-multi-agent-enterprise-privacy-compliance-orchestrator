/**
 * Microsoft Teams Adaptive Card integration.
 *
 * Sends compliance alerts to a Teams channel via an Incoming Webhook URL.
 * The card includes severity colour-coding, entity breakdown, and one-click
 * approve / reject action buttons (requires Power Automate flow for approval
 * callback in production).
 */
import https from 'https';
import { URL } from 'url';
import { logger } from '../infrastructure/logger';

export interface ComplianceAlert {
  alert_id: string;
  event_id: string;
  source_system?: string;
  xai_explanation: string;
  proposed_redaction_policy: string;
  severity?: string;
  triggered_frameworks?: string[];
}

const SEVERITY_COLOURS: Record<string, string> = {
  CRITICAL: 'attention',
  HIGH: 'warning',
  MEDIUM: 'good',
  LOW: 'accent',
  INFO: 'default',
};

export class TeamsIntegration {
  private readonly webhookUrl: string | undefined;

  constructor(webhookUrl?: string) {
    this.webhookUrl = webhookUrl ?? process.env.TEAMS_WEBHOOK_URL;
  }

  async sendApprovalRequest(alert: ComplianceAlert): Promise<void> {
    const colour = SEVERITY_COLOURS[alert.severity ?? 'INFO'] ?? 'default';
    const frameworks =
      alert.triggered_frameworks?.join(', ') ?? 'N/A';

    // Adaptive Card payload (Adaptive Cards Schema 1.4)
    const card = {
      type: 'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          content: {
            $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
            type: 'AdaptiveCard',
            version: '1.4',
            body: [
              {
                type: 'TextBlock',
                text: '🔐 Data Privacy Compliance Alert',
                weight: 'Bolder',
                size: 'Large',
                color: colour,
              },
              {
                type: 'FactSet',
                facts: [
                  { title: 'Alert ID', value: alert.alert_id },
                  { title: 'Event Source', value: alert.event_id },
                  { title: 'Source System', value: alert.source_system ?? 'Unknown' },
                  { title: 'Severity', value: alert.severity ?? 'Unknown' },
                  { title: 'Frameworks', value: frameworks },
                ],
              },
              {
                type: 'TextBlock',
                text: '**XAI Analysis**',
                weight: 'Bolder',
              },
              {
                type: 'TextBlock',
                text: alert.xai_explanation,
                wrap: true,
              },
              {
                type: 'TextBlock',
                text: `**Proposed Policy:** ${alert.proposed_redaction_policy}`,
                wrap: true,
              },
            ],
            actions: [
              {
                type: 'Action.Submit',
                title: '✅ Approve Remediation',
                style: 'positive',
                data: { alertId: alert.alert_id, action: 'approve_remediation' },
              },
              {
                type: 'Action.Submit',
                title: '❌ Reject',
                style: 'destructive',
                data: { alertId: alert.alert_id, action: 'reject' },
              },
            ],
          },
        },
      ],
    };

    if (!this.webhookUrl) {
      logger.info('[Teams] No webhook URL configured – logging card payload', {
        alert_id: alert.alert_id,
        card: JSON.stringify(card),
      });
      return;
    }

    await this._post(this.webhookUrl, card);
    logger.info('[Teams] Adaptive Card sent', { alert_id: alert.alert_id });
  }

  private _post(webhookUrl: string, body: unknown): Promise<void> {
    return new Promise((resolve, reject) => {
      const data = Buffer.from(JSON.stringify(body), 'utf8');
      const url = new URL(webhookUrl);
      const options = {
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': data.byteLength,
        },
      };

      const req = https.request(options, (res) => {
        if ((res.statusCode ?? 0) >= 400) {
          reject(new Error(`Teams webhook returned HTTP ${res.statusCode}`));
        } else {
          resolve();
        }
        res.resume();
      });

      req.on('error', reject);
      req.write(data);
      req.end();
    });
  }
}
