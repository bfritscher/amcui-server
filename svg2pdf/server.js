const http = require('http');
const stream = require('stream');
const puppeteer = require('puppeteer');

async function createPDF(svgContent) {
    const htmlContent = createHTMLTemplate(svgContent);

    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.setContent(htmlContent, { waitUntil: 'domcontentloaded' });

    const dimensions = await page.evaluate(() => {
        const svg = document.querySelector('svg');
        return {
            width: svg.getBBox().width,
            height: svg.getBBox().height
        };
    });

    const pdfBuffer = await page.pdf({
        width: `${dimensions.width}px`,
        height: `${dimensions.height}px`,
        printBackground: true
    });

    await browser.close();
    return pdfBuffer;
}

function createHTMLTemplate(svgContent) {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SVG to PDF</title>
            <style>
                body, html {
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }
                svg {
                    width: 100%;
                    height: 100%;
                }
            </style>
        </head>
        <body>
            ${svgContent}
        </body>
        </html>
    `;
}

const server = http.createServer(async (req, res) => {
    if (req.method === 'POST' && req.url === '/convert') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString('utf8');
        });

        req.on('end', async () => {
            try {
                const pdfBuffer = await createPDF(body);
                const readStream = new stream.PassThrough();
                readStream.end(pdfBuffer);
                res.setHeader('Content-Disposition', 'attachment; filename=converted.pdf');
                res.setHeader('Content-Type', 'application/pdf');
                res.setHeader('Content-Length', pdfBuffer.length);
                readStream.pipe(res);
            } catch (error) {
                console.error(error);
                res.statusCode = 500;
                res.end('Error generating PDF');
            }
        });
    } else {
        res.statusCode = 404;
        res.end('Not Found');
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});