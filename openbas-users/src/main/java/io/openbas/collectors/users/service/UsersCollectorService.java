package io.openbas.collectors.users.service;

import io.openbas.database.model.User;
import io.openbas.database.repository.UserRepository;

import java.util.List;

import static io.openbas.helper.StreamHelper.fromIterable;

public class UsersCollectorService implements Runnable {

    private final UserRepository userRepository;

    public UsersCollectorService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void run() {
        List<User> users = fromIterable(userRepository.findAll());
        System.out.println("User collector provisioning based on " + users.size() + " users");
    }
}
