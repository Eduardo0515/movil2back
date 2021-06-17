const app = require('./app')
require('./connection')

async function init(){
    await app.listen(3000);
    console.log('Server on LocalHost:3000')
}

init();