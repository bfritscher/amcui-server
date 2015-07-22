module.exports = function (grunt) {
    // Project configuration.
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        nodemon: {
            dev: {
                script: 'dist/server.js'
            },
            options: {
                ignore: ['node_modules/**', 'Gruntfile.js'],
                nodeArgs: ['--debug'],
                env: {
                    PORT: '8181'
                }
            }
        },

        watch: {
            scripts: {
                files: ['*.ts', '!node_modules/**/*.ts'], // the watched files
                tasks: ["newer:tslint:all", "ts:build"], // the task to run
                options: {
                    spawn: false // makes the watch task faster
                }
            }
        },

        concurrent: {
            watchers: {
                tasks: ['nodemon', 'watch'],
                options: {
                    logConcurrentOutput: true
                }
            }
        },

        tslint: {
            options: {
                configuration: grunt.file.readJSON("tslint.json")
            },
            all: {
                src: ["*.ts", "!node_modules/**/*.ts", "!obj/**/*.ts", "!typings/**/*.ts"] // avoid linting typings files and node_modules files
            }
        },

        ts: {
            build: {
                src: ["*.ts", "!node_modules/**/*.ts"], // Avoid compiling TypeScript files in node_modules
                outDir: 'dist',
                options: {
                    module: 'commonjs', // To compile TypeScript using external modules like NodeJS
                    fast: 'never', // You'll need to recompile all the files each time for NodeJS
                    compiler: './node_modules/typescript/bin/tsc'
                }
            }
        }
    });

    grunt.loadNpmTasks("grunt-ts");
    grunt.loadNpmTasks("grunt-tslint");
    grunt.loadNpmTasks("grunt-contrib-watch");
    grunt.loadNpmTasks("grunt-nodemon");
    grunt.loadNpmTasks("grunt-concurrent");
    grunt.loadNpmTasks("grunt-newer");

    // Default tasks.
    grunt.registerTask("serve", ["default", "concurrent:watchers"]);
    grunt.registerTask('default', ["tslint:all", "ts:build"]);
};