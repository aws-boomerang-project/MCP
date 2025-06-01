import { MCPConverseClient } from './MCPConverseClient.js';
import chalk from 'chalk';
import { serverConfig } from './config/bedrock.js';
import express from 'express';

const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;

async function main() {
    const serverUrl = serverConfig.url;
    const apiToken = serverConfig.apiToken;
    const client = new MCPConverseClient(serverUrl, apiToken);
    
    try {
        await client.connect();
        console.log(chalk.cyan('Connected to MCP server'));
        console.log(chalk.cyan('Container is running and waiting for Lex inputs...\n'));

        app.get('/health', (req, res) => {
            res.status(200).json({ status: 'healthy' });
        });

        // Set up Express endpoint for Lex
        app.post('/chat', async (req, res) => {
            try {
                const { inputText } = req.body;
                console.log(chalk.blue(`Received input from Lex: ${inputText}`));
                // Log environment variables for debugging
                console.log('Environment variables:', {
                    MCP_URL: process.env.MCP_URL,
                    MCP_TOKEN: process.env.MCP_TOKEN,
                    AWS_REGION: process.env.AWS_REGION
                });

                // Process the input using your existing client
                const result = await client.processUserInput(inputText);
                console.log(chalk.green(`Response from MCP: ${result}`));

                // Send response back to Lex
                res.json({
                    statusCode: 200,
                    body: {
                        response: result
                    }
                });

                // Reset timeout since we received input
                resetTimeout();
            } catch (error) {
                console.error(chalk.red('Error processing input:'), error);
                res.status(500).json({
                    statusCode: 500,
                    error: 'Internal Server Error'
                });
            }
        });

        // Start the server
        app.listen(PORT, () => {
            console.log(chalk.green(`Server listening on port ${PORT}`));
        });

        // Timeout handling
        let shutdownTimeout: NodeJS.Timeout;
        
        function resetTimeout() {
            // Clear existing timeout
            if (shutdownTimeout) {
                clearTimeout(shutdownTimeout);
            }
            
            // Set new timeout (3 minutes)
            shutdownTimeout = setTimeout(async () => {
                console.log(chalk.yellow('No input received for 3 minutes. Shutting down...'));
                await handleShutdown(client);
            }, 3 * 60 * 1000); // 3 minutes in milliseconds
        }

        // Initial timeout set
        resetTimeout();

        // Graceful shutdown handling
        process.on('SIGINT', async () => {
            console.log(chalk.yellow('\nReceived SIGINT. Cleaning up...'));
            await handleShutdown(client);
        });

        process.on('SIGTERM', async () => {
            console.log(chalk.yellow('\nReceived SIGTERM. Cleaning up...'));
            await handleShutdown(client);
        });

    } catch (error) {
        console.error(chalk.red('Error:'), error);
        process.exit(1);
    }
}

async function handleShutdown(client: MCPConverseClient) {
    try {
        await client.close();
        console.log(chalk.cyan('\nGoodbye!'));
        process.exit(0);
    } catch (error) {
        console.error(chalk.red('Error during shutdown:'), error);
        process.exit(1);
    }
}

// Error handling
process.on('uncaughtException', (error) => {
    console.error(chalk.red('Uncaught Exception:'), error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error(chalk.red('Unhandled Rejection at:'), promise, chalk.red('reason:'), reason);
    process.exit(1);
});

main();