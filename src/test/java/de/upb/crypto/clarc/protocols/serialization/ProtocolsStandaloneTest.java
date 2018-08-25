package de.upb.crypto.clarc.protocols.serialization;

import de.upb.crypto.clarc.protocols.serialization.classes.*;
import de.upb.crypto.clarc.utils.GenericStandaloneTest;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;

class ProtocolsStandaloneTest extends GenericStandaloneTest {

    @Override
    protected String getPackageName() {
        return "de.upb.crypto.clarc.protocols";
    }

    @Override
    protected Collection<StandaloneTestParams> getStandaloneClasses() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        toReturn.addAll(ExpressionsParams.get());
        toReturn.addAll(ParameterParams.get());
        toReturn.addAll(GeneralizedSchnorrParams.get());
        toReturn.addAll(DamgardParams.get());
        toReturn.addAll(FiatShamirParams.get());
        return toReturn;
    }

    @Override
    @ParameterizedTest
    @ArgumentsSource(ProtocolsStandaloneTest.class)
    public void testForConstructor(StandaloneTestParams params) throws NoSuchMethodException {
        runTestForConstructor(params);
    }

    @Override
    @ParameterizedTest
    @ArgumentsSource(ProtocolsStandaloneTest.class)
    public void checkForOverrideHashCode(StandaloneTestParams params) throws NoSuchMethodException {
        runCheckForOverrideHashCode(params);
    }

    @Override
    @ParameterizedTest
    @ArgumentsSource(ProtocolsStandaloneTest.class)
    public void checkIfAllClassesOverrideEquals(StandaloneTestParams params) throws NoSuchMethodException {
        runCheckIfAllClassesOverrideEquals(params);
    }

    @Override
    @ParameterizedTest
    @ArgumentsSource(ProtocolsStandaloneTest.class)
    public void testRecreateRepresentable(
            StandaloneTestParams params) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, InstantiationException {
        runTestRecreateRepresentable(params);
    }
}
