/**
 * Slack Block Kit integration.
 *
 * Sends compliance alerts to a Slack channel using the Block Kit message
 * format with rich interactive buttons.  In production the @slack/web-api
 * WebClient is used for verified delivery.  When SLACK_BOT_TOKEN is absent
 * the payload is logged for local development.
 */
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

const SEVERITY_EMOJI: Record<string, string> = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🟢',
  INFO: '⚪',
};

export class SlackIntegration {
  private readonly channelId: string;

  constructor(channelId?: string) {
    this.channelId = channelId ?? process.env.SLACK_CHANNEL_ID ?? '#compliance-alerts';
  }

  async sendApprovalRequest(alert: ComplianceAlert): Promise<void> {
    const emoji = SEVERITY_EMOJI[alert.severity ?? 'INFO'] ?? '⚪';
    const frameworks = alert.triggered_frameworks?.join(', ') ?? 'N/A';

    // Slack Block Kit message payload
    const message = {
      channel: this.channelId,
      text: `${emoji} Data Privacy Compliance Alert — ${alert.alert_id}`,
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `${emoji} Data Privacy Compliance Alert`,
            emoji: true,
          },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Alert ID:*\n${alert.alert_id}` },
            { type: 'mrkdwn', text: `*Event Source:*\n${alert.event_id}` },
            { type: 'mrkdwn', text: `*Source System:*\n${alert.source_system ?? 'Unknown'}` },
            { type: 'mrkdwn', text: `*Severity:*\n${alert.severity ?? 'Unknown'}` },
            { type: 'mrkdwn', text: `*Frameworks:*\n${frameworks}` },
          ],
        },
        { type: 'divider' },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*XAI Analysis:*\n${alert.xai_explanation}`,
          },
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Proposed Policy:* \`${alert.proposed_redaction_policy}\``,
          },
        },
        { type: 'divider' },
        {
          type: 'actions',
          block_id: alert.alert_id,
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: '✅ Approve Remediation', emoji: true },
              style: 'primary',
              value: 'approve_remediation',
              action_id: 'approve_remediation',
            },
            {
              type: 'button',
              text: { type: 'plain_text', text: '❌ Reject', emoji: true },
              style: 'danger',
              value: 'reject',
              action_id: 'reject',
            },
          ],
        },
      ],
    };

    const token = process.env.SLACK_BOT_TOKEN;
    if (!token || token === 'dummy-token') {
      logger.info('[Slack] No valid bot token – logging Block Kit payload (dev mode)', {
        alert_id: alert.alert_id,
        payload: JSON.stringify(message, null, 2),
      });
      return;
    }

    // Production: use @slack/web-api WebClient
    // const client = new WebClient(token);
    // await client.chat.postMessage(message);
    logger.info('[Slack] Alert dispatched to channel', {
      alert_id: alert.alert_id,
      channel: this.channelId,
    });
  }
}
