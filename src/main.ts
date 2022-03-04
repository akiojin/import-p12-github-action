import * as core from '@actions/core'
import * as os from 'os'
import * as tmp from 'tmp'
import * as coreCommand from '@actions/core/lib/command'
import * as fsPromises from 'fs/promises';
import { Security } from './Security'

const IsPost = !!process.env[`STATE_POST`]
const IsMacOS = os.platform() === 'darwin'

function AllowPostProcess()
{
	coreCommand.issueCommand('save-state', { name: 'POST' }, 'true')
}

const CustomKeychain = `${process.env.HOME}/Library/Keychains/temp-apple-certificate.keychain-db`

async function Run()
{
	try {
		const P12Base64: string = core.getInput('p12-base64')
		const P12Password: string = core.getInput('p12-password')
		const keychainPassword: string = core.getInput('keychain-password') || Math.random().toString(36)

		core.setSecret(keychainPassword)

		if (P12Base64 === '') {
			throw new Error('p12-base64 is null')
		}
		if (P12Password === '') {
			throw new Error('p12-password is null')
		}

		const P12File = tmp.fileSync()
		await fsPromises.writeFile(P12File.name, Buffer.from(P12Base64, 'base64'))

		await Security.CreateKeychain(CustomKeychain, keychainPassword)
		await Security.UnlockKeychain(CustomKeychain, keychainPassword)
		await Security.ImportCertificateFromFile(CustomKeychain, P12File.name, P12Password)
		await Security.SetListKeychains(CustomKeychain)
		await Security.AllowAccessForAppleTools(CustomKeychain, keychainPassword)
		await Security.ShowListKeychains()
		await Security.ShowCodeSignings(CustomKeychain)
	} catch (ex: any) {
		core.setFailed(ex.message)
	}
}

async function Cleanup()
{
	core.info('Cleanup')

	try {
		await Security.DeleteKeychain(CustomKeychain)
	} catch (ex: any) {
		core.setFailed(ex.message)
	}
}

if (!IsMacOS) {
	core.setFailed('Action requires macOS agent.')
} else {
	if (!!IsPost) {
		Cleanup()
	} else {
		Run()
	}
	
	AllowPostProcess()
}
