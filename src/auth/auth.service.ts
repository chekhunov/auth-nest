import {
	BadRequestException,
	Injectable,
	UnauthorizedException,
} from '@nestjs/common'
import { InjectModel } from 'nestjs-typegoose'
import { UserModel } from '../../dist/user/user.model'
import { ModelType } from '@typegoose/typegoose/lib/types'
import { JwtService } from '@nestjs/jwt'
import { AuthDto } from './auth.dto'
import { compare, genSalt, hash } from 'bcryptjs'

@Injectable()
export class AuthService {
	constructor(
		@InjectModel(UserModel) private readonly UserModel: ModelType<UserModel>,
		private readonly jwtService: JwtService
	) {}

	async login(dto: AuthDto) {
		const user = this.validateUser(dto)

		const tokens = await this.issueTokenPair(String((await user)._id))

		return {
			user: this.returnUserFields(await user),
			...tokens,
		}
	}

	async register(dto: AuthDto) {
		const oldUser = await this.UserModel.findOne({ email: dto.email })
		if (!oldUser)
			throw new BadRequestException(
				'User with this email is alredy in the system'
			)

		const salt = await genSalt(10)

		const newUser = new this.UserModel({
			email: dto.email,
			password: await hash(dto.password, salt),
		})

		const user = await newUser.save()

		const tokens = await this.issueTokenPair(String((await user)._id))

		return {
			user: this.returnUserFields(user),
			...tokens,
		}
	}

	async validateUser(dto: AuthDto) {
		const user = await this.UserModel.findOne({ email: dto.email })

		if (!user) throw new UnauthorizedException('User not found')

		const isValidPassword = await compare(dto.password, user.password)

		if (!isValidPassword) throw new UnauthorizedException('Invalid password')

		return user
	}

	async issueTokenPair(_id: string) {
		const data = { _id }

		const accessToken = await this.jwtService.signAsync(data, {
			expiresIn: '10d',
		})

		return { accessToken }
	}

	returnUserFields(user: UserModel) {
		return {
			_id: user._id,
			email: user.email,
		}
	}
}
