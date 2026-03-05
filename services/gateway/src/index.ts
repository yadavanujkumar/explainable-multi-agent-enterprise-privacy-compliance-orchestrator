import express from 'express';
import { Kafka } from 'kafkajs';
import { SlackIntegration } from './application/SlackIntegration';

const app = express();
app.use(express.json());

const port = process.env.PORT || 3000;
const broker = process.env.KAFKA_BROKER || 'localhost:9092';

const kafka = new Kafka({
  clientId: 'gateway-service',
  brokers: [broker]
});

const consumer = kafka.consumer({ groupId: 'gateway-group' });
const producer = kafka.producer();
const slackIntegration = new SlackIntegration();

app.post('/webhook/slack', async (req, res) => {
  try {
    const payload = req.body;
    // Simple verification for Slack Interactive Components
    if (payload.type === 'interactive_message') {
        const action = payload.actions[0].value;
        const alertId = payload.callback_id;
        
        if (action === 'approve_remediation') {
            await producer.send({
                topic: 'remediation_actions',
                messages: [
                    { value: JSON.stringify({ alertId, status: 'APPROVED', timestamp: new Date().toISOString() }) }
                ]
            });
            console.log(`[Zero-Trust Audit Log] Remediation approved for alert ${alertId} by user ${payload.user.name}`);
            return res.status(200).send('Remediation Approved and Applied.');
        }
    }
    res.status(200).send('OK');
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).send('Internal Server Error');
  }
});

async function start() {
  await producer.connect();
  await consumer.connect();
  await consumer.subscribe({ topic: 'compliance_alerts', fromBeginning: false });

  console.log('Gateway connected to Kafka.');

  await consumer.run({
    eachMessage: async ({ topic, partition, message }) => {
      if (!message.value) return;
      const alert = JSON.parse(message.value.toString());
      console.log(`Received compliance alert: ${alert.alert_id}`);
      
      // Trigger external integration
      await slackIntegration.sendApprovalRequest(alert);
    },
  });

  app.listen(port, () => {
    console.log(`Gateway listening on port ${port}`);
  });
}

start().catch(console.error);