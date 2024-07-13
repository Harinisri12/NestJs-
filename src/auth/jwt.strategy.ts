import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { DatabaseService } from "../database/database.service"; // Ensure correct path to DatabaseService

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(private readonly databaseService: DatabaseService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: "Secret"
        });
    }

    async validate(payload: { email: string }) {
        console.log(payload)
        const user = await this.databaseService.user.findFirst({
            where: {
                email: payload.email,
            },
        });
        return user; // Assuming this is your database model or entity
    }
}
