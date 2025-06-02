import axios from 'axios';

export const handler = async (event) => {
    console.log('Event:', JSON.stringify(event, null, 2));

    try {
        // Get input from either slot or direct input
        const userInput = event.inputTranscript || 
                         event.sessionState.intent.slots.userMessage?.value;

        // Call your ECS endpoint
        const albEndpoint = '[$DESIRED-ENDPOINT]/chat';
        
        const response = await axios.post(albEndpoint, {
            query: userInput,
            sessionId: event.sessionState.sessionId
        });

        return {
            sessionState: {
                dialogAction: {
                    type: 'ElicitIntent'  // Keep conversation open
                },
                intent: {
                    name: 'ECSIntent',
                    slots: {
                        userMessage: {
                            value: userInput
                        }
                    },
                    state: 'Fulfilled'
                }
            },
            messages: [
                {
                    contentType: 'PlainText',
                    content: response.data.body.response
                }
            ]
        };
    } catch (error) {
        console.error('Error:', error);
        
        return {
            sessionState: {
                dialogAction: {
                    type: 'ElicitIntent'
                },
                intent: {
                    name: 'ECSIntent',
                    slots: event.sessionState.intent.slots,
                    state: 'InProgress'
                }
            },
            messages: [
                {
                    contentType: 'PlainText',
                    content: 'I encountered an issue. Please try again.'
                }
            ]
        };
    }
};