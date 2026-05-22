package com.konfigyr.crypto;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertyName;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.scheduling.config.TriggerTask;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.scheduling.support.PeriodicTrigger;

import java.time.Duration;

/**
 * A {@link SchedulingConfigurer} that registers a single {@link TriggerTask} with
 * the {@link ScheduledTaskRegistrar}.
 * <p>
 * Instances are created via {@link #of(String, Environment, Runnable)}, which reads
 * the task's trigger configuration from the application {@link Environment} under
 * {@code konfigyr.crypto.tasks.<name>} and selects either a
 * {@link CronTrigger} ({@code cron} property) or a {@link PeriodicTrigger}
 * ({@code interval} property). When both are set, {@code cron} takes precedence.
 * <p>
 * If no properties are bound for the given task name, the default trigger fires
 * every {@literal 1 hour}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeysetTaskAutoConfiguration
 **/
@Slf4j
@NullMarked
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
final class KeysetTaskRegistration implements SchedulingConfigurer {

	static final ConfigurationPropertyName PREFIX = ConfigurationPropertyName.of("konfigyr.crypto.tasks");

	static final TriggerProperties DEFAULT_PROPERTIES = new TriggerProperties(null, Duration.ofHours(1), true);

	private final TriggerTask task;

	/**
	 * Creates a {@link KeysetTaskRegistration} for the given task name by constructing a
	 * {@link org.springframework.scheduling.Trigger} from the {@link Environment}.
	 * <p>
	 * Properties are read from {@code konfigyr.crypto.tasks.<name>}. If no properties are
	 * bound, {@link #DEFAULT_PROPERTIES} (1-hour periodic trigger) is used. When both
	 * {@code cron} and {@code interval} are configured, {@code cron} takes precedence and
	 * a warning is logged.
	 *
	 * @param name the task name used to look up properties and for log messages,
	 *        can't be {@literal null}
	 * @param environment the application environment to bind trigger properties from,
	 *        can't be {@literal null}
	 * @param runnable the task logic to execute on each trigger fire, can't be {@literal null}
	 * @return the task registration, never {@literal null}
	 * @throws IllegalArgumentException when the bound properties have neither {@code cron}
	 *         nor {@code interval} set
	 */
	static KeysetTaskRegistration of(String name, Environment environment, Runnable runnable) {
		final ConfigurationPropertyName path = PREFIX.append(name);
		final TriggerProperties properties = Binder.get(environment)
				.bind(PREFIX.append(name), Bindable.of(TriggerProperties.class))
				.orElse(DEFAULT_PROPERTIES);

		if (properties.cron() != null) {
			if (properties.interval() != null) {
				log.warn("Keyset task '{}' has both 'cron' and 'interval' configured under '{}'; 'cron' takes precedence",
					name, path);
			}
			return new KeysetTaskRegistration(new TriggerTask(runnable, new CronTrigger(properties.cron())));
		}

		if (properties.interval() != null) {
			return new KeysetTaskRegistration(new TriggerTask(runnable, new PeriodicTrigger(properties.interval())));
		}

		throw new IllegalArgumentException("Keyset task '" + name + "' requires either 'cron' or 'interval' to be " +
			"set under the following configuration prefix: '" + path + "'.");
	}

	@Override
	public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
		taskRegistrar.addTriggerTask(task);
	}

	/**
	 * Trigger configuration for a single keyset maintenance task.
	 *
	 * @param cron optional cron expression; when set, takes precedence over {@code interval}
	 * @param interval optional fixed-rate period; used when {@code cron} is {@literal null}
	 * @param enabled whether this task should be registered; checked via
	 *        {@link org.springframework.boot.autoconfigure.condition.ConditionalOnProperty}
	 *        before the bean is created
	 */
	record TriggerProperties(@Nullable String cron, @Nullable Duration interval, boolean enabled) {

	}

}
