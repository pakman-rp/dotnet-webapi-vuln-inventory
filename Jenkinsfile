pipeline {
    agent any

    environment {
        SEVERITY_THRESHOLD = 'HIGH'
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }
        stage('Restore & Build') {
            steps {
                sh 'dotnet restore'
                sh 'dotnet build --no-restore'
            }
        }
        stage('Unit Tests') {
            steps { sh 'dotnet test --no-build || true' }
        }
        stage('Secret Scan') {
            steps { echo 'PLACEHOLDER - run gitleaks/trufflehog CLI, publish report' }
        }
        stage('SAST Scan') {
            steps { echo 'PLACEHOLDER - run vendor SAST CLI (Checkmarx/Fortify/Semgrep/SonarQube/etc.)' }
        }
        stage('SCA + SBOM') {
            steps { echo 'PLACEHOLDER - run vendor SCA CLI, generate CycloneDX/SPDX SBOM' }
        }
        stage('Severity Gate') {
            steps { echo "PLACEHOLDER - fail pipeline if findings >= ${SEVERITY_THRESHOLD}" }
        }
    }

    post {
        always {
            echo 'Archive SAST/SCA/secret-scan reports here for POC evidence.'
        }
    }
}
