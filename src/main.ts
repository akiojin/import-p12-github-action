import * as core from '@actions/core'
import * as os from 'os'
import * as tmp from 'tmp'
import * as fs from 'fs/promises';
import { Security } from './Security'

const IsMacOS = os.platform() === 'darwin'

async function Run()
{
	try {
		const P12Base64: string = core.getInput('p12-base64')
		const P12Password: string = core.getInput('p12-password')

		if (P12Base64 === '') {
			throw new Error('p12-base64 is null.')
		}
		if (P12Password === '') {
			throw new Error('p12-password is null.')
		}

		const keychainPassword: string = core.getInput('keychain-password')
		if (keychainPassword === '') {
			throw new Error('keychain-password is null.')
		}
		core.setSecret(keychainPassword)

		let keychain: string = core.getInput('keychain')
		if (keychain === '') {
			keychain = `${process.env.HOME}/Library/Keychains/login.keychain-db`
		}

		const P12File = tmp.fileSync()
		await fs.writeFile(P12File.name, Buffer.from(P12Base64, 'base64'))

		await Security.UnlockKeychain(keychain, keychainPassword)
		await Security.ImportCertificateFromFile(keychain, P12File.name, P12Password)
		await Security.SetListKeychains(keychain)
		await Security.AllowAccessForAppleTools(keychain, keychainPassword)

		await Security.ShowListKeychains()
		await Security.ShowCodeSignings(keychain)
	} catch (ex: any) {
		core.setFailed(ex.message)
	}
}

if (!IsMacOS) {
	core.setFailed('Action requires macOS agent.')
} else {
	Run()
}
